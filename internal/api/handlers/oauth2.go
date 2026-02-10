package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/lib/pq"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/core/auth"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/consts"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	fositejwt "github.com/ory/fosite/token/jwt"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type OAuth2Handler struct {
	Provider *auth.Provider
	DB       *gorm.DB
	KeyMgr   *auth.KeyManager
	Config   *config.Config
}

func NewOAuth2Handler(p *auth.Provider, db *gorm.DB, km *auth.KeyManager, cfg *config.Config) *OAuth2Handler {
	return &OAuth2Handler{
		Provider: p,
		DB:       db,
		KeyMgr:   km,
		Config:   cfg,
	}
}

func generateRandomString(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func getEffectiveLifespan(clientVal, globalVal string, fallback time.Duration) time.Duration {
	if clientVal != "" {
		if d, err := time.ParseDuration(clientVal); err == nil {
			return d
		}
	}
	if globalVal != "" {
		if d, err := time.ParseDuration(globalVal); err == nil {
			return d
		}
	}
	return fallback
}

func (h *OAuth2Handler) getIssuer(c *gin.Context) string {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		return strings.TrimRight(h.Provider.Config.IDTokenIssuer, "/")
	}
	base := strings.TrimRight(h.Provider.Config.IDTokenIssuer, "/")
	return fmt.Sprintf("%s/t/%s", base, tenantID)
}

func (h *OAuth2Handler) Authorize(c *gin.Context) {
	ctx := c.Request.Context()

	// Parse the authorization request
	ar, err := h.Provider.Fosite.NewAuthorizeRequest(ctx, c.Request)
	if err != nil {
		h.Provider.Fosite.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	// Validate Tenant and Client ownership
	tenantID := c.Param("tenant_id")
	clientID := ar.GetClient().GetID()

	var client models.OAuth2Client
	if err := h.DB.First(&client, "id = ? AND tenant_id = ?", clientID, tenantID).Error; err != nil {
		logger.Log.Warn("Client/Tenant mismatch or not found",
			zap.String("client_id", clientID),
			zap.String("tenant_id", tenantID))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "client not found in this tenant"})
		return
	}

	// Strict Scope Validation: Client cannot request scopes it doesn't have
	requestedScopes := ar.GetRequestedScopes()
	allowedScopes := make(map[string]bool)
	for _, s := range client.Scopes {
		allowedScopes[s] = true
	}

	for _, reqScope := range requestedScopes {
		if !allowedScopes[reqScope] {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_scope",
				"error_description": fmt.Sprintf("The requested scope '%s' is not authorized for this client.", reqScope),
			})
			return
		}
	}

	// OIDC Compliance Checks (prompt, max_age, session)
	prompt := ar.GetRequestForm().Get("prompt")
	// maxAge parameter can be used to validate auth_time age in future implementations
	// maxAge := ar.GetRequestForm().Get("max_age")

	sessionCookie, err := c.Cookie(consts.SessionCookieName)
	hasSession := err == nil && sessionCookie != ""

	if prompt == "none" && !hasSession {
		h.Provider.Fosite.WriteAuthorizeError(ctx, c.Writer, ar, fosite.ErrLoginRequired)
		return
	}

	forceLogin := prompt == "login"

	verifier := c.Query("login_verifier")
	var userID string
	isRemembered := false
	var authTime time.Time = time.Now()

	if verifier != "" {
		var loginReq models.LoginRequest
		if err := h.DB.First(&loginReq, "id = ? AND authenticated = ?", verifier, true).Error; err != nil {
			logger.Log.Warn("Invalid or expired login verifier", zap.String("verifier", verifier))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_login_verifier"})
			return
		}
		userID = loginReq.Subject
		isRemembered = loginReq.Remember
		authTime = loginReq.UpdatedAt

	} else if hasSession && !forceLogin {
		userID = sessionCookie

		var lastLogin models.LoginRequest
		if err := h.DB.Order("updated_at desc").
			Where("subject = ? AND authenticated = ?", userID, true).
			First(&lastLogin).Error; err == nil {

			authTime = lastLogin.UpdatedAt
		} else {
			forceLogin = true
		}

		if !forceLogin {
			var userCheck models.User
			if err := h.DB.Select("id").First(&userCheck, "id = ? AND is_active = ?", userID, true).Error; err != nil {
				forceLogin = true
			}
		}
	}

	if userID == "" || forceLogin {
		challengeID, err := generateRandomString(32)
		if err != nil {
			logger.Log.Error("Failed to generate challenge", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal_server_error"})
			return
		}

		loginReq := models.LoginRequest{
			ID:                challengeID,
			ClientID:          clientID,
			RequestedScope:    pq.StringArray(ar.GetRequestedScopes()),
			RequestedAudience: pq.StringArray(ar.GetRequestedAudience()),
			RequestURL:        c.Request.RequestURI,
			ClientIP:          c.ClientIP(),
			Active:            true,
			Authenticated:     false,
			CreatedAt:         time.Now(),
			UpdatedAt:         time.Now(),
		}

		if err := h.DB.Create(&loginReq).Error; err != nil {
			logger.Log.Error("Failed to save login request", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "database_error"})
			return
		}

		redirectURL := fmt.Sprintf("%s?login_challenge=%s", h.Config.ExternalLoginURL, challengeID)
		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	var grantedScopes []string
	var grantedAudience []string

	forceConsent := prompt == "consent"

	if !client.SkipConsent || forceConsent {
		consentVerifier := c.Query("consent_verifier")

		if consentVerifier != "" {
			var consentReq models.ConsentRequest
			if err := h.DB.First(&consentReq, "id = ? AND authenticated = ?", consentVerifier, true).Error; err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_consent_verifier"})
				return
			}
			grantedScopes = consentReq.GrantedScope
			grantedAudience = consentReq.GrantedAudience
		} else {
			challengeID, _ := generateRandomString(32)
			consentReq := models.ConsentRequest{
				ID:                challengeID,
				ClientID:          clientID,
				Subject:           userID,
				RequestedScope:    pq.StringArray(ar.GetRequestedScopes()),
				RequestedAudience: pq.StringArray(ar.GetRequestedAudience()),
				RequestURL:        c.Request.RequestURI,
				Active:            true,
				Authenticated:     false,
				CreatedAt:         time.Now(),
				UpdatedAt:         time.Now(),
			}
			if err := h.DB.Create(&consentReq).Error; err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "database_error"})
				return
			}
			redirectURL := fmt.Sprintf("%s?consent_challenge=%s", h.Config.ExternalConsentURL, challengeID)
			c.Redirect(http.StatusFound, redirectURL)
			return
		}
	} else {
		grantedScopes = ar.GetRequestedScopes()
		grantedAudience = ar.GetRequestedAudience()
	}

	accessTokenLife := getEffectiveLifespan(client.AccessTokenLifespan, h.Config.AccessTokenLifespan, 1*time.Hour)
	refreshTokenLife := getEffectiveLifespan(client.RefreshTokenLifespan, h.Config.RefreshTokenLifespan, 720*time.Hour) // 30 gün
	idTokenLife := getEffectiveLifespan(client.IDTokenLifespan, h.Config.IDTokenLifespan, 1*time.Hour)

	if isRemembered {
		refreshTokenLife = refreshTokenLife * 3
	}

	hasOfflineAccess := false
	for _, s := range grantedScopes {
		if s == "offline_access" {
			hasOfflineAccess = true
			break
		}
	}

	issuer := h.getIssuer(c)
	now := time.Now()

	session := &openid.DefaultSession{
		Claims: &fositejwt.IDTokenClaims{
			Issuer:      issuer,
			Subject:     userID,
			Audience:    grantedAudience,
			IssuedAt:    now,
			RequestedAt: now,
			AuthTime:    authTime,
			ExpiresAt:   now.Add(idTokenLife),
		},
		Headers: &fositejwt.Headers{
			Extra: map[string]interface{}{"kid": consts.SigningKeyID},
		},
		Subject: userID,
	}

	session.ExpiresAt[fosite.AccessToken] = now.Add(accessTokenLife)
	if hasOfflineAccess {
		session.ExpiresAt[fosite.RefreshToken] = now.Add(refreshTokenLife)
	} else {
		session.ExpiresAt[fosite.RefreshToken] = now.Add(accessTokenLife)
	}

	var user models.User
	if err := h.DB.First(&user, "id = ?", userID).Error; err == nil {
		session.Claims.Add("tenant_id", tenantID)
		mappedClaims := auth.MapUserClaims(&user, grantedScopes)
		for k, v := range mappedClaims {
			session.Claims.Add(k, v)
		}
	} else {
		logger.Log.Error("User not found for token claims", zap.String("user_id", userID))
	}

	for _, scope := range grantedScopes {
		ar.GrantScope(scope)
	}
	for _, audience := range grantedAudience {
		ar.GrantAudience(audience)
	}

	response, err := h.Provider.Fosite.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		h.Provider.Fosite.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	h.Provider.Fosite.WriteAuthorizeResponse(ctx, c.Writer, ar, response)
}

func (h *OAuth2Handler) Token(c *gin.Context) {
	ctx := c.Request.Context()
	session := &openid.DefaultSession{}
	ar, err := h.Provider.Fosite.NewAccessRequest(ctx, c.Request, session)
	if err != nil {
		h.Provider.Fosite.WriteAccessError(ctx, c.Writer, ar, err)
		return
	}

	urlTenantID := c.Param("tenant_id")
	client := ar.GetClient()

	var dbClient models.OAuth2Client
	if err := h.DB.Select("tenant_id").First(&dbClient, "id = ?", client.GetID()).Error; err != nil {
		h.Provider.Fosite.WriteAccessError(ctx, c.Writer, ar, fosite.ErrServerError)
		return
	}

	if dbClient.TenantID != urlTenantID {
		logger.Log.Warn("Tenant mismatch attack attempt",
			zap.String("client_id", client.GetID()),
			zap.String("attempted_tenant", urlTenantID),
			zap.String("actual_tenant", dbClient.TenantID))
		h.Provider.Fosite.WriteAccessError(ctx, c.Writer, ar, fosite.ErrInvalidClient)
		return
	}

	response, err := h.Provider.Fosite.NewAccessResponse(ctx, ar)
	if err != nil {
		h.Provider.Fosite.WriteAccessError(ctx, c.Writer, ar, err)
		return
	}

	h.Provider.Fosite.WriteAccessResponse(ctx, c.Writer, ar, response)
}

func (h *OAuth2Handler) Logout(c *gin.Context) {
	c.SetCookie(consts.SessionCookieName, "", -1, "/", "", h.Config.CookieSecure, true)

	postLogoutRedirectURI := c.Query("post_logout_redirect_uri")
	idTokenHint := c.Query("id_token_hint")
	state := c.Query("state")

	if postLogoutRedirectURI == "" {
		c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out."})
		return
	}

	isValidRedirect := false

	if idTokenHint != "" {
		token, err := jwt.ParseSigned(idTokenHint)
		if err == nil {
			claims := &jwt.Claims{}
			if err := token.UnsafeClaimsWithoutVerification(claims); err == nil {
				if len(claims.Audience) > 0 {
					clientID := claims.Audience[0]

					var client models.OAuth2Client
					if err := h.DB.First(&client, "id = ?", clientID).Error; err == nil {
						for _, allowedURI := range client.PostLogoutRedirectURIs {
							if allowedURI == postLogoutRedirectURI {
								isValidRedirect = true
								break
							}
						}
					}
				}
			}
		}
	}

	if isValidRedirect {
		if state != "" {
			sep := "?"
			if strings.Contains(postLogoutRedirectURI, "?") {
				sep = "&"
			}
			postLogoutRedirectURI += sep + "state=" + state
		}
		c.Redirect(http.StatusFound, postLogoutRedirectURI)
	} else {
		c.JSON(http.StatusOK, gin.H{
			"message": "Logged out. (Redirect blocked due to missing or invalid validation)",
		})
	}
}

func (h *OAuth2Handler) Introspect(c *gin.Context) {
	ctx := c.Request.Context()
	session := &openid.DefaultSession{}
	ar, err := h.Provider.Fosite.NewIntrospectionRequest(ctx, c.Request, session)
	if err != nil {
		h.Provider.Fosite.WriteIntrospectionError(ctx, c.Writer, err)
		return
	}
	h.Provider.Fosite.WriteIntrospectionResponse(ctx, c.Writer, ar)
}

func (h *OAuth2Handler) Revoke(c *gin.Context) {
	ctx := c.Request.Context()
	err := h.Provider.Fosite.NewRevocationRequest(ctx, c.Request)
	if err != nil {
		h.Provider.Fosite.WriteRevocationResponse(ctx, c.Writer, err)
		return
	}
	h.Provider.Fosite.WriteRevocationResponse(ctx, c.Writer, nil)
}

func (h *OAuth2Handler) UserInfo(c *gin.Context) {
	token := fosite.AccessTokenFromRequest(c.Request)
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})
		return
	}

	ctx := c.Request.Context()
	_, ar, err := h.Provider.Fosite.IntrospectToken(ctx, token, fosite.AccessToken, &openid.DefaultSession{})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	session := ar.GetSession().(*openid.DefaultSession)
	userID := session.GetSubject()

	var user models.User
	if err := h.DB.First(&user, "id = ?", userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user_not_found"})
		return
	}

	grantedScopes := ar.GetGrantedScopes()
	userInfo := auth.MapUserClaims(&user, grantedScopes)
	userInfo["sub"] = user.ID
	userInfo["email_verified"] = true

	c.JSON(200, userInfo)
}

func (h *OAuth2Handler) Jwks(c *gin.Context) {
	privKey := h.KeyMgr.GetActivePrivateKey()
	jwks := auth.GeneratePublicJWKS(privKey)
	c.JSON(200, jwks)
}

func (h *OAuth2Handler) Discover(c *gin.Context) {
	issuer := h.getIssuer(c)

	c.JSON(200, gin.H{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/oauth2/auth",
		"token_endpoint":         issuer + "/oauth2/token",
		"jwks_uri":               issuer + "/.well-known/jwks.json",
		"userinfo_endpoint":      issuer + "/userinfo",
		"revocation_endpoint":    issuer + "/oauth2/revoke",
		"introspection_endpoint": issuer + "/oauth2/introspect",
		"end_session_endpoint":   issuer + "/oauth2/logout",

		"response_types_supported":              []string{"code", "token", "id_token", "code id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "offline_access", "profile", "email", "phone", "address"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "iss", "name", "email", "email_verified", "tenant_id", "phone_number", "address", "auth_time"},
		"display_values_supported":              []string{"page", "popup"},
		"ui_locales_supported":                  []string{"en-US", "tr-TR"},
	})
}
