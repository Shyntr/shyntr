package handlers

import (
	"encoding/json"
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
	"github.com/nevzatcirak/shyntr/pkg/utils"
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
	return &OAuth2Handler{Provider: p, DB: db, KeyMgr: km, Config: cfg}
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

func (h *OAuth2Handler) resolveTenantID(c *gin.Context) string {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		return h.Config.DefaultTenantID
	}
	return tenantID
}

func (h *OAuth2Handler) getIssuer(c *gin.Context) string {
	tenantID := h.resolveTenantID(c)
	base := strings.TrimRight(h.Provider.Config.IDTokenIssuer, "/")
	if c.Param("tenant_id") == "" {
		return base
	}
	return fmt.Sprintf("%s/t/%s", base, tenantID)
}

func (h *OAuth2Handler) Authorize(c *gin.Context) {
	ctx := c.Request.Context()
	ar, err := h.Provider.Fosite.NewAuthorizeRequest(ctx, c.Request)
	if err != nil {
		h.Provider.Fosite.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	tenantID := h.resolveTenantID(c)
	clientID := ar.GetClient().GetID()

	var client models.OAuth2Client
	if err := h.DB.First(&client, "id = ? AND tenant_id = ?", clientID, tenantID).Error; err != nil {
		logger.Log.Warn("Client/Tenant mismatch or not found", zap.String("client_id", clientID), zap.String("tenant_id", tenantID))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "client not found in this tenant"})
		return
	}

	if client.EnforcePKCE {
		if ar.GetRequestForm().Get("code_challenge") == "" {
			h.Provider.Fosite.WriteAuthorizeError(ctx, c.Writer, ar, fosite.ErrInvalidRequest.WithHint("This client requires PKCE. Please include code_challenge."))
			return
		}
	}

	requestedAudience := ar.GetRequestedAudience()
	if len(requestedAudience) > 0 && len(client.Audience) > 0 {
		allowedAudience := make(map[string]bool)
		for _, a := range client.Audience {
			allowedAudience[a] = true
		}
		for _, reqAud := range requestedAudience {
			if !allowedAudience[reqAud] {
				h.Provider.Fosite.WriteAuthorizeError(ctx, c.Writer, ar, fosite.ErrInvalidRequest.WithHintf("The requested audience '%s' is not whitelisted for this client.", reqAud))
				return
			}
		}
	}

	requestedScopes := ar.GetRequestedScopes()
	allowedScopes := make(map[string]bool)
	for _, s := range client.Scopes {
		allowedScopes[s] = true
	}

	for _, reqScope := range requestedScopes {
		if !allowedScopes[reqScope] {
			h.Provider.Fosite.WriteAuthorizeError(ctx, c.Writer, ar, fosite.ErrInvalidScope.WithHintf("The requested scope '%s' is not authorized for this client.", reqScope))
			return
		}
	}

	prompt := ar.GetRequestForm().Get("prompt")
	sessionCookie, _ := c.Cookie(consts.SessionCookieName)
	hasSession := sessionCookie != ""

	if prompt == "none" && !hasSession {
		h.Provider.Fosite.WriteAuthorizeError(ctx, c.Writer, ar, fosite.ErrLoginRequired)
		return
	}

	forceLogin := prompt == "login"
	verifier := c.Query("login_verifier")

	var userID string
	var authTime time.Time = time.Now()
	var userContext map[string]interface{}
	isRemembered := false
	rememberForDuration := 0

	if verifier != "" {
		var loginReq models.LoginRequest
		if err := h.DB.First(&loginReq, "id = ? AND authenticated = ?", verifier, true).Error; err == nil {
			userID = loginReq.Subject
			authTime = loginReq.UpdatedAt
			isRemembered = loginReq.Remember
			rememberForDuration = loginReq.RememberFor

			if len(loginReq.Context) > 0 {
				if err := json.Unmarshal(loginReq.Context, &userContext); err != nil {
					logger.Log.Error("Failed to unmarshal user context", zap.Error(err))
				}
			}
		} else {
			logger.Log.Warn("Invalid or expired login verifier", zap.String("verifier", verifier))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_login_verifier"})
			return
		}

	} else if hasSession && !forceLogin {
		userID = sessionCookie
		var lastLogin models.LoginRequest
		if err := h.DB.Order("updated_at desc").Where("subject = ? AND authenticated = ?", userID, true).First(&lastLogin).Error; err == nil {
			authTime = lastLogin.UpdatedAt
			isRemembered = lastLogin.Remember
			rememberForDuration = lastLogin.RememberFor
			if len(lastLogin.Context) > 0 {
				if err := json.Unmarshal(lastLogin.Context, &userContext); err != nil {
					logger.Log.Error("Failed to unmarshal SSO user context", zap.Error(err))
				}
			}
		}
	}

	if userID == "" || forceLogin {
		challengeID, err := utils.GenerateRandomHex(16)
		if err != nil {
			logger.Log.Error("Failed to generate challenge", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal_server_error"})
			return
		}

		loginReq := models.LoginRequest{
			ID:                challengeID,
			TenantID:          tenantID,
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

		redirectURL := fmt.Sprintf("%s?login_challenge=%s&tenant_id=%s", h.Config.ExternalLoginURL, challengeID, tenantID)
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
			challengeID, _ := utils.GenerateRandomHex(16)
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
	idTokenLife := getEffectiveLifespan(client.IDTokenLifespan, h.Config.IDTokenLifespan, 1*time.Hour)
	refreshTokenLife := getEffectiveLifespan(client.RefreshTokenLifespan, h.Config.RefreshTokenLifespan, 720*time.Hour)

	if isRemembered {
		if rememberForDuration > 0 {
			refreshTokenLife = time.Duration(rememberForDuration) * time.Second
		} else {
			refreshTokenLife = refreshTokenLife * 3
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
		Subject:   userID,
		ExpiresAt: make(map[fosite.TokenType]time.Time),
	}

	session.ExpiresAt[fosite.AccessToken] = now.Add(accessTokenLife)

	hasOfflineAccess := false
	for _, s := range grantedScopes {
		if s == "offline_access" {
			hasOfflineAccess = true
			break
		}
	}

	if hasOfflineAccess {
		session.ExpiresAt[fosite.RefreshToken] = now.Add(refreshTokenLife)
	} else {
		session.ExpiresAt[fosite.RefreshToken] = now.Add(accessTokenLife)
	}

	session.Claims.Add("tenant_id", tenantID)
	if userContext != nil {
		mappedClaims := auth.MapClaims(userID, userContext, grantedScopes)
		for k, v := range mappedClaims {
			session.Claims.Add(k, v)
		}
	}

	for _, scope := range grantedScopes {
		ar.GrantScope(scope)
	}
	for _, aud := range grantedAudience {
		ar.GrantAudience(aud)
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

	urlTenantID := h.resolveTenantID(c)
	var dbClient models.OAuth2Client
	if err := h.DB.Select("tenant_id").First(&dbClient, "id = ?", ar.GetClient().GetID()).Error; err != nil {
		h.Provider.Fosite.WriteAccessError(ctx, c.Writer, ar, fosite.ErrInvalidClient)
		return
	}

	if dbClient.TenantID != urlTenantID {
		logger.Log.Warn("Tenant mismatch", zap.String("client_id", ar.GetClient().GetID()), zap.String("tenant_id", urlTenantID))
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
			if err := token.UnsafeClaimsWithoutVerification(claims); err == nil && len(claims.Audience) > 0 {
				var client models.OAuth2Client
				if err := h.DB.First(&client, "id = ?", claims.Audience[0]).Error; err == nil {
					for _, uri := range client.PostLogoutRedirectURIs {
						if uri == postLogoutRedirectURI {
							isValidRedirect = true
							break
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
		c.JSON(http.StatusOK, gin.H{"message": "Logged out (Redirect blocked due to validation failure)"})
	}
}

func (h *OAuth2Handler) UserInfo(c *gin.Context) {
	token := fosite.AccessTokenFromRequest(c.Request)
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})
		return
	}

	session := &openid.DefaultSession{}
	_, accessRequest, err := h.Provider.Fosite.IntrospectToken(c.Request.Context(), token, fosite.AccessToken, session)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	sess, ok := accessRequest.GetSession().(*openid.DefaultSession)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid_session_type"})
		return
	}

	subject := sess.Subject
	if subject == "" && sess.Claims != nil {
		subject = sess.Claims.Subject
	}

	var userCtx map[string]interface{}
	var loginReq models.LoginRequest

	if subject != "" {
		err = h.DB.Where("subject = ? AND authenticated = ?", subject, true).
			Order("updated_at desc").
			First(&loginReq).Error

		if err == nil && len(loginReq.Context) > 0 {
			json.Unmarshal(loginReq.Context, &userCtx)
		}
	}

	if userCtx == nil || len(userCtx) == 0 {
		if sess.Claims != nil && sess.Claims.Extra != nil {
			userCtx = sess.Claims.Extra
		} else {
			userCtx = make(map[string]interface{})
		}
	}

	grantedScopes := accessRequest.GetGrantedScopes()

	if len(grantedScopes) == 0 && sess.Claims != nil && sess.Claims.Extra != nil {
		if scopeStr, ok := sess.Claims.Extra["scope"].(string); ok {
			grantedScopes = strings.Split(scopeStr, " ")
		}
	}

	safeClaims := auth.MapClaims(subject, userCtx, grantedScopes)

	c.JSON(http.StatusOK, safeClaims)
}

func (h *OAuth2Handler) Introspect(c *gin.Context) {
	session := &openid.DefaultSession{}
	ar, err := h.Provider.Fosite.NewIntrospectionRequest(c.Request.Context(), c.Request, session)
	if err != nil {
		h.Provider.Fosite.WriteIntrospectionError(c.Request.Context(), c.Writer, err)
		return
	}
	h.Provider.Fosite.WriteIntrospectionResponse(c.Request.Context(), c.Writer, ar)
}

func (h *OAuth2Handler) Revoke(c *gin.Context) {
	err := h.Provider.Fosite.NewRevocationRequest(c.Request.Context(), c.Request)
	h.Provider.Fosite.WriteRevocationResponse(c.Request.Context(), c.Writer, err)
}

func (h *OAuth2Handler) Jwks(c *gin.Context) {
	privKey := h.KeyMgr.GetActivePrivateKey()
	jwks := auth.GeneratePublicJWKS(privKey)
	c.JSON(http.StatusOK, jwks)
}

// Discover endpoints handles .well-known/openid-configuration
// Ensures ALL OIDC discovery fields are present.
func (h *OAuth2Handler) Discover(c *gin.Context) {
	tenantID := h.resolveTenantID(c)

	var tenant models.Tenant
	if err := h.DB.Select("id").First(&tenant, "id = ?", tenantID).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "tenant_not_found"})
		return
	}

	issuer := h.getIssuer(c)
	makeURL := func(path string) string { return issuer + path }

	c.JSON(http.StatusOK, gin.H{
		"issuer":                 issuer,
		"authorization_endpoint": makeURL("/oauth2/auth"),
		"token_endpoint":         makeURL("/oauth2/token"),
		"jwks_uri":               makeURL("/.well-known/jwks.json"),
		"userinfo_endpoint":      makeURL("/userinfo"),
		"revocation_endpoint":    makeURL("/oauth2/revoke"),
		"introspection_endpoint": makeURL("/oauth2/introspect"),
		"end_session_endpoint":   makeURL("/oauth2/logout"),

		"response_types_supported": []string{
			"code",
			"token",
			"id_token",
			"code id_token",
			"code token",
			"code id_token token",
		},

		"response_modes_supported": []string{"query", "fragment", "form_post"},

		"grant_types_supported": []string{
			"authorization_code",
			"implicit",
			"refresh_token",
			"client_credentials",
		},

		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},

		"scopes_supported": []string{"openid", "offline_access", "profile", "email", "address", "phone"},

		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "private_key_jwt"},

		"claims_supported": []string{"sub", "iss", "tenant_id", "name", "email", "email_verified", "phone_number", "address", "auth_time"},

		"display_values_supported": []string{"page", "popup"},
		"ui_locales_supported":     []string{"en-US", "tr-TR"},
	})
}
