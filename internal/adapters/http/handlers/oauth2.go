package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/iam"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	utils2 "github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/consts"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/Shyntr/shyntr/pkg/utils"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/lib/pq"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	fositejwt "github.com/ory/fosite/token/jwt"
	"go.uber.org/zap"
)

type OAuth2Handler struct {
	Provider         *utils2.Provider
	KeyMgr           utils2.KeyManager
	Config           *config.Config
	OAuth2ClientUse  usecase.OAuth2ClientUseCase
	OAuth2SessionUse usecase.OAuth2SessionUseCase
	AuthReq          usecase.AuthUseCase
	OIDCConnUse      usecase.OIDCConnectionUseCase
	TenantUse        usecase.TenantUseCase
	ScopeUse         usecase.ScopeUseCase
	JWKSCache        *utils2.JWKSCache
}

func NewOAuth2Handler(p *utils2.Provider, km utils2.KeyManager, cfg *config.Config, OAuth2ClientUse usecase.OAuth2ClientUseCase,
	AuthReq usecase.AuthUseCase, OAuth2SessionUse usecase.OAuth2SessionUseCase, OIDCConnUse usecase.OIDCConnectionUseCase,
	TenantUse usecase.TenantUseCase, ScopeUse usecase.ScopeUseCase, jwksCache *utils2.JWKSCache) *OAuth2Handler {
	return &OAuth2Handler{Provider: p, KeyMgr: km, Config: cfg, OAuth2ClientUse: OAuth2ClientUse, AuthReq: AuthReq,
		OAuth2SessionUse: OAuth2SessionUse, TenantUse: TenantUse, OIDCConnUse: OIDCConnUse, ScopeUse: ScopeUse, JWKSCache: jwksCache}
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
	tenantID := c.Param(consts.ContextKeyTenantID)
	if tenantID == "" {
		return h.Config.DefaultTenantID
	}
	return tenantID
}

func (h *OAuth2Handler) getIssuer(c *gin.Context) string {
	tenantID := h.resolveTenantID(c)
	base := strings.TrimRight(h.Config.BaseIssuerURL, "/")
	if c.Param(consts.ContextKeyTenantID) == "" {
		return base
	}
	return fmt.Sprintf("%s/t/%s", base, tenantID)
}

func (h *OAuth2Handler) resolveSessionSubject(c *gin.Context, ctx context.Context) *model.LoginRequest {
	sessionToken, err := c.Cookie(consts.SessionCookieName)
	if err != nil || sessionToken == "" {
		return nil
	}
	loginReq, err := h.AuthReq.GetLoginRequestBySessionToken(ctx, sessionToken)
	if err != nil {
		logger.FromGin(c).Debug("Session token lookup failed, treating as unauthenticated")
		return nil
	}
	return loginReq
}

// Authorize godoc
// @Summary OAuth2 Authorization Endpoint
// @Description Handles the initial step of the OAuth 2.1 authorization code flow. Enforces PKCE, tenant boundaries, and redirects the user agent to the login or consent UI.
// @Tags OAuth2/OIDC Core
// @Produce html
// @Param client_id query string true "OAuth2 Client ID"
// @Param response_type query string true "Must be 'code'"
// @Param redirect_uri query string true "Registered redirect URI"
// @Param scope query string false "Requested space-separated scopes"
// @Param state query string false "Opaque value used to maintain state between the request and the callback"
// @Param code_challenge query string false "PKCE code challenge (Required if client enforces PKCE)"
// @Param code_challenge_method query string false "PKCE method, e.g., 'S256'"
// @Param prompt query string false "Forces login or consent (e.g., 'login', 'consent', 'none')"
// @Success 302 {string} string "Redirects to login UI, consent UI, or the client's redirect URI with an authorization code"
// @Failure 400 {object} map[string]string "Bad Request (e.g., missing PKCE, invalid redirect URI)"
// @Failure 403 {object} map[string]string "Forbidden (e.g., client not found in tenant)"
// @Router /oauth2/auth [get]
// @Router /t/{tenant_id}/oauth2/auth [get]
func (h *OAuth2Handler) Authorize(c *gin.Context) {
	tenantID := h.resolveTenantID(c)

	ctx := context.WithValue(c.Request.Context(), consts.ContextKeyTenantID, tenantID)

	ar, err := h.Provider.GetFosite(tenantID).NewAuthorizeRequest(ctx, c.Request)
	if err != nil {
		h.Provider.GetFosite(tenantID).WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	clientID := ar.GetClient().GetID()

	client, err := h.OAuth2ClientUse.GetClientByTenant(ctx, tenantID, clientID)
	if err != nil {
		logger.FromGin(c).Warn("Client/Tenant mismatch or not found", zap.String("client_id", clientID), zap.String(consts.ContextKeyTenantID, tenantID))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "client not found in this tenant"})
		return
	}

	if client.EnforcePKCE {
		if ar.GetRequestForm().Get("code_challenge") == "" {
			h.Provider.GetFosite(tenantID).WriteAuthorizeError(ctx, c.Writer, ar, fosite.ErrInvalidRequest.WithHint("OAuth 2.1 policy requires PKCE for all clients. Please include code_challenge."))
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
				h.Provider.GetFosite(tenantID).WriteAuthorizeError(ctx, c.Writer, ar, fosite.ErrInvalidRequest.WithHintf("The requested audience '%s' is not whitelisted for this client.", reqAud))
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
			h.Provider.GetFosite(tenantID).WriteAuthorizeError(ctx, c.Writer, ar, fosite.ErrInvalidScope.WithHintf("The requested scope '%s' is not authorized for this client.", reqScope))
			return
		}
	}

	prompt := ar.GetRequestForm().Get("prompt")
	forceLogin := prompt == "login"
	verifier := c.Query("login_verifier")

	var userID string
	var authTime time.Time = time.Now()
	var userContext map[string]interface{}
	var consentContext map[string]interface{}
	isRemembered := false
	rememberForDuration := 0

	if verifier != "" {
		loginReq, loginErr := h.AuthReq.GetAuthenticatedLoginRequest(ctx, verifier)
		if loginErr == nil {
			userID = loginReq.Subject
			authTime = loginReq.UpdatedAt
			isRemembered = loginReq.Remember
			rememberForDuration = loginReq.RememberFor

			if len(loginReq.Context) > 0 {
				if err := json.Unmarshal(loginReq.Context, &userContext); err != nil {
					logger.FromGin(c).Error("Failed to unmarshal user context", zap.Error(err))
				}
			}
		} else {
			logger.FromGin(c).Warn("Invalid or expired login verifier")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_login_verifier"})
			return
		}

	} else if !forceLogin {
		if sessionLoginReq := h.resolveSessionSubject(c, ctx); sessionLoginReq != nil {
			userID = sessionLoginReq.Subject
			authTime = sessionLoginReq.UpdatedAt
			isRemembered = sessionLoginReq.Remember
			rememberForDuration = sessionLoginReq.RememberFor
			if len(sessionLoginReq.Context) > 0 {
				if err := json.Unmarshal(sessionLoginReq.Context, &userContext); err != nil {
					logger.FromGin(c).Error("Failed to unmarshal SSO user context", zap.Error(err))
				}
			}
		}
	}

	if prompt == "none" && userID == "" {
		h.Provider.GetFosite(tenantID).WriteAuthorizeError(ctx, c.Writer, ar, fosite.ErrLoginRequired)
		return
	}

	if userID == "" || forceLogin {
		challengeID, err := utils.GenerateRandomHex(16)
		if err != nil {
			logger.FromGin(c).Error("Failed to generate challenge", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal_server_error"})
			return
		}

		request := model.LoginRequest{
			ID:                challengeID,
			TenantID:          tenantID,
			ClientID:          clientID,
			RequestedScope:    pq.StringArray(ar.GetRequestedScopes()),
			RequestedAudience: pq.StringArray(ar.GetRequestedAudience()),
			RequestURL:        c.Request.RequestURI,
			Protocol:          "oidc",
			ClientIP:          c.ClientIP(),
			Active:            true,
			Authenticated:     false,
			CreatedAt:         time.Now(),
			UpdatedAt:         time.Now(),
		}

		_, savedErr := h.AuthReq.CreateLoginRequest(ctx, &request)
		if savedErr != nil {
			logger.FromGin(c).Error("Failed to save login request", zap.Error(savedErr))
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
			consentReq, consentReqErr := h.AuthReq.GetAuthenticatedConsentRequest(ctx, consentVerifier)
			if consentReqErr != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_consent_verifier"})
				return
			}
			if len(consentReq.Context) > 0 {
				if err := json.Unmarshal(consentReq.Context, &consentContext); err != nil {
					logger.FromGin(c).Error("Failed to unmarshal SSO consent context", zap.Error(err))
				}
			}
			grantedScopes = consentReq.GrantedScope
			grantedAudience = consentReq.GrantedAudience
		} else {
			challengeID, _ := utils.GenerateRandomHex(16)
			request := model.ConsentRequest{
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
			_, consentReqErr := h.AuthReq.CreateConsentRequest(ctx, &request)
			if consentReqErr != nil {
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
	session := model.NewJWTSession(userID, "")
	session.DefaultSession = &openid.DefaultSession{
		Claims: &fositejwt.IDTokenClaims{
			Issuer:      issuer,
			Subject:     userID,
			Audience:    grantedAudience,
			IssuedAt:    now,
			RequestedAt: now,
			AuthTime:    authTime,
			ExpiresAt:   now.Add(idTokenLife),
			Extra:       map[string]interface{}{"client_id": clientID, "auth_time": time.Now().Unix(), "amr": []string{"pwd"}},
		},
		Headers: &fositejwt.Headers{
			Extra: map[string]interface{}{"kid": consts.SigningKeyID},
		},
		Subject:   userID,
		ExpiresAt: make(map[fosite.TokenType]time.Time),
	}

	session.ExpiresAt[fosite.AccessToken] = now.Add(accessTokenLife)
	session.JWTClaims.Issuer = issuer
	session.JWTClaims.Subject = userID
	session.JWTClaims.Audience = grantedAudience
	session.JWTClaims.Extra["client_id"] = clientID
	session.JWTClaims.Extra["auth_time"] = time.Now().Unix()
	session.JWTClaims.Extra["amr"] = []string{"pwd"}

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

	session.Claims.Add(consts.ContextKeyTenantID, tenantID)
	session.JWTClaims.Extra[consts.ContextKeyTenantID] = tenantID

	if consentContext != nil {
		for k, v := range consentContext {
			session.Claims.Add(k, v)
			session.JWTClaims.Extra[k] = v
		}
	}

	if userContext != nil {
		scopeEntities, err := h.ScopeUse.GetScopesByNames(ctx, tenantID, grantedScopes)
		if err != nil {
			logger.FromGin(c).Error("Failed to fetch dynamic scopes", zap.Error(err))
		}

		mappedClaims := utils2.MapClaims(userID, userContext, scopeEntities)
		for k, v := range mappedClaims {
			session.Claims.Add(k, v)
			session.JWTClaims.Extra[k] = v
		}
	}

	for _, scope := range grantedScopes {
		ar.GrantScope(scope)
	}
	for _, aud := range grantedAudience {
		ar.GrantAudience(aud)
	}

	response, err := h.Provider.GetFosite(tenantID).NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		h.Provider.GetFosite(tenantID).WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	h.OAuth2SessionUse.RecordAuthorization(ctx, ar.GetID(), tenantID, clientID, c.ClientIP(), c.Request.UserAgent(), grantedScopes)
	h.Provider.GetFosite(tenantID).WriteAuthorizeResponse(ctx, c.Writer, ar, response)
}

// Token godoc
// @Summary OAuth2 Token Endpoint
// @Description Issues access tokens, ID tokens, and refresh tokens based on the provided grant type (e.g., authorization_code, client_credentials, refresh_token). Enforces tenant isolation.
// @Tags OAuth2/OIDC Core
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param grant_type formData string true "Grant Type (e.g., 'authorization_code', 'client_credentials')"
// @Param client_id formData string false "OAuth2 Client ID"
// @Param client_secret formData string false "OAuth2 Client Secret (for basic/post auth)"
// @Param code formData string false "Authorization code (if grant_type=authorization_code)"
// @Param redirect_uri formData string false "Registered redirect URI (must match the one in the auth request)"
// @Param code_verifier formData string false "PKCE code verifier (if PKCE was used)"
// @Param refresh_token formData string false "Refresh token (if grant_type=refresh_token)"
// @Success 200 {object} map[string]interface{} "Returns access_token, id_token, refresh_token, and expires_in"
// @Failure 400 {object} map[string]interface{} "Bad Request (e.g., invalid grant, invalid client)"
// @Router /oauth2/token [post]
// @Router /t/{tenant_id}/oauth2/token [post]
func (h *OAuth2Handler) Token(c *gin.Context) {
	tenantID := h.resolveTenantID(c)

	fositeEngine := h.Provider.GetFosite(tenantID)
	ctx := context.WithValue(c.Request.Context(), consts.ContextKeyTenantID, tenantID)
	emptySession := model.NewJWTSession("", "")
	ar, err := fositeEngine.NewAccessRequest(ctx, c.Request, emptySession)
	if err != nil {
		logger.LogFositeError(c, err, "Failed to create access request in TokenEndpoint")
		fositeEngine.WriteAccessError(ctx, c.Writer, ar, err)
		return
	}

	dbClient, dbClientErr := h.OAuth2ClientUse.GetClient(ctx, ar.GetClient().GetID())
	if dbClientErr != nil {
		logger.FromGin(c).Warn("Client not found", zap.String("client_id", ar.GetClient().GetID()), zap.String(consts.ContextKeyTenantID, tenantID))
		fositeEngine.WriteAccessError(ctx, c.Writer, ar, fosite.ErrInvalidClient)
		return
	}

	if dbClient.TenantID != tenantID {
		logger.FromGin(c).Warn("Tenant mismatch detected", zap.String("client_id", ar.GetClient().GetID()), zap.String(consts.ContextKeyTenantID, tenantID))
		fositeEngine.WriteAccessError(ctx, c.Writer, ar, fosite.ErrInvalidClient)
		return
	}

	response, err := fositeEngine.NewAccessResponse(ctx, ar)
	if err != nil {
		logger.LogFositeError(c, err, "Failed to create access response in TokenEndpoint")
		fositeEngine.WriteAccessError(ctx, c.Writer, ar, err)
		return
	}
	h.OAuth2SessionUse.RecordTokenIssuance(ctx, ar.GetID(), tenantID, ar.GetClient().GetID(), c.ClientIP(), c.Request.UserAgent(), ar.GetGrantedScopes())
	fositeEngine.WriteAccessResponse(ctx, c.Writer, ar, response)
}

// Logout godoc
// @Summary OpenID Connect RP-Initiated Logout
// @Description Terminates the user's session. Supports id_token_hint for validation and post_logout_redirect_uri for safe redirection. Also propagates logout to federated IdPs if applicable.
// @Tags OAuth2/OIDC Core
// @Produce html
// @Param id_token_hint query string false "Previously issued ID Token to validate the logout request"
// @Param post_logout_redirect_uri query string false "Registered URI to redirect after successful logout"
// @Param state query string false "Opaque value to maintain state"
// @Success 200 {object} map[string]string "Returns a success message if no redirect URI is provided"
// @Success 302 {string} string "Redirects to post_logout_redirect_uri"
// @Router /oauth2/logout [get]
// @Router /t/{tenant_id}/oauth2/logout [get]
func (h *OAuth2Handler) Logout(c *gin.Context) {
	tenantID := h.resolveTenantID(c)
	postLogoutRedirectURI := c.Query("post_logout_redirect_uri")
	idTokenHint := c.Query("id_token_hint")
	state := c.Query("state")

	var subject string
	var idTokenAudience string

	if idTokenHint != "" {
		allowedAlgs := []jose.SignatureAlgorithm{jose.RS256}
		token, err := jwt.ParseSigned(idTokenHint, allowedAlgs)
		if err == nil {
			_, cert, _, err := h.KeyMgr.GetActiveKeys(c.Request.Context(), "sig")
			if err != nil {
				logger.FromGin(c).Error("failed to load active crypto keys")
			}
			if cert != nil {
				type CustomClaims struct {
					jwt.Claims
					TenantID string `json:"tenant_id"`
				}
				var claims CustomClaims
				if err := token.Claims(cert.PublicKey, &claims); err == nil {
					subject = claims.Subject
					if len(claims.Audience) > 0 {
						idTokenAudience = claims.Audience[0]
					}
					if claims.TenantID != "" {
						tenantID = claims.TenantID
					}
				} else {
					logger.FromGin(c).Warn("id_token_hint signature verification failed during logout attempt", zap.Error(err))
				}
			}
		}
	}
	ctx := context.WithValue(c.Request.Context(), consts.ContextKeyTenantID, tenantID)
	if subject == "" {
		if sessionLoginReq := h.resolveSessionSubject(c, ctx); sessionLoginReq != nil {
			subject = sessionLoginReq.Subject
		}
	}

	isValidRedirect := false
	if postLogoutRedirectURI != "" {
		if idTokenAudience != "" {
			client, err := h.OAuth2ClientUse.GetClient(ctx, idTokenAudience)
			if err == nil {
				for _, uri := range client.PostLogoutRedirectURIs {
					if strings.TrimRight(uri, "/") == strings.TrimRight(postLogoutRedirectURI, "/") {
						isValidRedirect = true
						postLogoutRedirectURI = uri
						break
					}
				}
				if !isValidRedirect {
					logger.FromGin(c).Warn("Logout URI mismatch", zap.Strings("registered_uris", client.PostLogoutRedirectURIs), zap.String("requested_uri", postLogoutRedirectURI))
				}
			} else {
				logger.FromGin(c).Error("Logout GetClient failed", zap.Error(err), zap.String("tenant_id", tenantID), zap.String("client_id", idTokenAudience))
			}
		}
	} else {
		isValidRedirect = true
	}

	finalRedirect := postLogoutRedirectURI
	if isValidRedirect && finalRedirect != "" && state != "" {
		sep := "?"
		if strings.Contains(finalRedirect, "?") {
			sep = "&"
		}
		finalRedirect += sep + "state=" + state
	}

	if !isValidRedirect && postLogoutRedirectURI != "" {
		logger.FromGin(c).Warn("Logout redirect blocked", zap.String("requested_uri", postLogoutRedirectURI), zap.String("client_id", idTokenAudience))
		c.JSON(http.StatusOK, gin.H{"message": "Logged out locally (Redirect blocked due to validation failure)"})
		return
	}

	c.SetCookie(consts.SessionCookieName, "", -1, "/", "", h.Config.CookieSecure, true)
	if subject != "" {
		err := h.OAuth2SessionUse.DeleteByClient(ctx, subject, idTokenAudience)
		if err != nil {
			logger.LogFositeError(c, err, "Failed to delete session in TokenEndpoint")
		}
		h.OAuth2SessionUse.RecordLogout(ctx, subject, tenantID, idTokenAudience, c.ClientIP(), c.Request.UserAgent(), idTokenHint != "")
	}

	var idpSource string
	var lastLogin *model.LoginRequest
	if subject != "" {
		var err error
		lastLogin, err = h.AuthReq.GetAuthenticatedLoginRequestBySubject(ctx, subject)
		if err == nil {
			if len(lastLogin.Context) > 0 {
				var ctxData map[string]interface{}
				if err := json.Unmarshal(lastLogin.Context, &ctxData); err == nil {
					if loginClaims, ok := ctxData["login_claims"].(map[string]interface{}); ok {
						if idp, ok := loginClaims["idp"].(string); ok {
							idpSource = idp
						}
					}
				}
			}
		}
		if lastLogin != nil {
			tenantID = lastLogin.TenantID
		}
	}

	if idpSource != "" && idpSource != "local" {
		parts := strings.Split(idpSource, ":")
		if len(parts) == 2 {
			protocol := parts[0]
			connectionID := parts[1]

			if protocol == "oidc" {
				conn, err := h.OIDCConnUse.GetConnection(ctx, tenantID, connectionID)
				if err == nil && conn.EndSessionEndpoint != "" {
					logoutURL := conn.EndSessionEndpoint
					if finalRedirect != "" {
						logoutURL = fmt.Sprintf("%s?post_logout_redirect_uri=%s", conn.EndSessionEndpoint, url.QueryEscape(finalRedirect))
					}
					c.Redirect(http.StatusFound, logoutURL)
					return
				}
			} else if protocol == "saml" {
				relayParam := ""
				if finalRedirect != "" {
					relayParam = "&RelayState=" + url.QueryEscape(finalRedirect)
				}

				tokenParam := ""
				if idTokenHint != "" {
					tokenParam = "&id_token_hint=" + idTokenHint
				}

				tID := c.Param(consts.ContextKeyTenantID)
				if tID == "" {
					tID = h.Config.DefaultTenantID
				}

				redirectURL := fmt.Sprintf("%s/t/%s/saml/sp/slo?connection_id=%s%s%s",
					h.Config.BaseIssuerURL, tID, connectionID, tokenParam, relayParam)
				c.Redirect(http.StatusFound, redirectURL)
				return
			}
		}
	}

	if finalRedirect != "" {
		c.Redirect(http.StatusFound, finalRedirect)
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out."})
	}
}

// UserInfo godoc
// @Summary OIDC UserInfo Endpoint
// @Description Returns Claims about the authenticated End-User. Requires a valid Access Token.
// @Tags OAuth2/OIDC Core
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "User claims (e.g., sub, email, name) scoped by RBAC rules"
// @Failure 401 {object} map[string]string "Unauthorized (missing or invalid token)"
// @Failure 500 {object} map[string]string "Internal Server Error"
// @Router /userinfo [get]
// @Router /t/{tenant_id}/userinfo [get]
func (h *OAuth2Handler) UserInfo(c *gin.Context) {
	tenantID := h.resolveTenantID(c)
	token := fosite.AccessTokenFromRequest(c.Request)
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})
		return
	}

	session := model.NewJWTSession("", "")
	_, accessRequest, err := h.Provider.GetFosite(tenantID).IntrospectToken(c.Request.Context(), token, fosite.AccessToken, session)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	sess, ok := accessRequest.GetSession().(*model.JWTSession)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid_session_type"})
		return
	}

	subject := sess.Subject
	if subject == "" && sess.Claims != nil {
		subject = sess.Claims.Subject
	}

	var userCtx map[string]interface{}

	if subject != "" {
		loginReq, err := h.AuthReq.GetAuthenticatedLoginRequestBySubject(c, subject)
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

	scopeEntities, err := h.ScopeUse.GetScopesByNames(c.Request.Context(), tenantID, grantedScopes)
	if err != nil {
		logger.FromGin(c).Error("Failed to fetch dynamic scopes", zap.Error(err))
	}

	safeClaims := utils2.MapClaims(subject, userCtx, scopeEntities)

	if _, exists := safeClaims["sub"]; !exists {
		safeClaims["sub"] = subject
	}

	client, isExtended := accessRequest.GetClient().(*iam.ExtendedClient)
	if !isExtended {
		c.JSON(http.StatusOK, safeClaims)
		return
	}

	alg := client.IDTokenEncryptedResponseAlg
	enc := client.IDTokenEncryptedResponseEnc

	if alg == "" {
		c.JSON(http.StatusOK, safeClaims)
		return
	}
	if enc == "" {
		enc = "A256GCM"
	}

	privKey, _, _, err := h.KeyMgr.GetActiveKeys(c.Request.Context(), "sig")
	if err != nil {
		logger.FromGin(c).Error("failed to load active crypto keys")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, nil)
	if err != nil {
		logger.FromGin(c).Error("Failed to initialize userinfo signer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	jwsToken, err := jwt.Signed(signer).Claims(safeClaims).Serialize()
	if err != nil {
		logger.FromGin(c).Error("Failed to sign userinfo", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	pubKey, err := h.JWKSCache.GetEncryptionKey(c.Request.Context(), client.JwksURI, alg)
	if err != nil || pubKey == nil {
		logger.FromGin(c).Warn("Cannot retrieve client encryption key for UserInfo", zap.String("client_id", client.GetID()), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "encryption_key_missing"})
		return
	}

	recipient := jose.Recipient{
		Algorithm: jose.KeyAlgorithm(alg),
		Key:       pubKey,
	}

	encrypter, err := jose.NewEncrypter(jose.ContentEncryption(enc), recipient, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	jweObject, err := encrypter.Encrypt([]byte(jwsToken))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "encryption_failed"})
		return
	}

	jweToken, _ := jweObject.CompactSerialize()

	c.Header("Content-Type", "application/jwt")
	c.String(http.StatusOK, jweToken)
}

// Introspect godoc
// @Summary Token Introspection Endpoint (RFC 7662)
// @Description Allows a protected resource (e.g., an API gateway) to query the active state and metadata of a given token.
// @Tags OAuth2/OIDC Core
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param token formData string true "The token to introspect"
// @Param client_id formData string false "OAuth2 Client ID"
// @Param client_secret formData string false "OAuth2 Client Secret"
// @Success 200 {object} map[string]interface{} "Introspection response (active boolean and token metadata)"
// @Router /oauth2/introspect [post]
// @Router /t/{tenant_id}/oauth2/introspect [post]
func (h *OAuth2Handler) Introspect(c *gin.Context) {
	tenantID := h.resolveTenantID(c)
	ctx := context.WithValue(c.Request.Context(), consts.ContextKeyTenantID, tenantID)
	session := model.NewJWTSession("", "")
	ar, err := h.Provider.GetFosite(tenantID).NewIntrospectionRequest(ctx, c.Request, session)
	if err != nil {
		h.Provider.GetFosite(tenantID).WriteIntrospectionError(ctx, c.Writer, err)
		return
	}
	h.Provider.GetFosite(tenantID).WriteIntrospectionResponse(ctx, c.Writer, ar)
}

// Revoke godoc
// @Summary Token Revocation Endpoint (RFC 7009)
// @Description Allows clients to notify the authorization server that a previously obtained refresh or access token is no longer needed.
// @Tags OAuth2/OIDC Core
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param token formData string true "The token to revoke"
// @Param token_type_hint formData string false "Hint about the token type (e.g., 'refresh_token' or 'access_token')"
// @Success 200 "Empty response on successful revocation (or if token didn't exist)"
// @Router /oauth2/revoke [post]
// @Router /t/{tenant_id}/oauth2/revoke [post]
func (h *OAuth2Handler) Revoke(c *gin.Context) {
	tenantID := h.resolveTenantID(c)
	ctx := context.WithValue(c.Request.Context(), consts.ContextKeyTenantID, tenantID)

	err := h.Provider.GetFosite(tenantID).NewRevocationRequest(ctx, c.Request)
	h.OAuth2SessionUse.RecordRevocation(ctx, tenantID, c.ClientIP(), c.Request.UserAgent(), err == nil)
	h.Provider.GetFosite(tenantID).WriteRevocationResponse(ctx, c.Writer, err)
}

// Jwks godoc
// @Summary JSON Web Key Set (JWKS) Endpoint
// @Description Returns the public keys used by the Authorization Server to sign JWTs (like ID Tokens). Used by clients to verify signatures.
// @Tags OAuth2/OIDC Core
// @Produce json
// @Success 200 {object} map[string]interface{} "The JWKS document containing an array of keys"
// @Router /.well-known/jwks.json [get]
// @Router /t/{tenant_id}/.well-known/jwks.json [get]
func (h *OAuth2Handler) Jwks(c *gin.Context) {
	jwks, err := h.KeyMgr.GetPublicJWKS(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "server_error",
			"message": "failed to generate JWKS document",
		})
		return
	}
	c.JSON(http.StatusOK, jwks)
}

// Discover godoc
// @Summary OpenID Connect Discovery Endpoint
// @Description Returns the OIDC Provider Configuration Document. Details the supported scopes, claims, and endpoints for a specific tenant.
// @Tags OAuth2/OIDC Core
// @Produce json
// @Success 200 {object} map[string]interface{} "The OIDC discovery metadata document"
// @Failure 404 {object} map[string]string "Tenant not found"
// @Router /.well-known/openid-configuration [get]
// @Router /t/{tenant_id}/.well-known/openid-configuration [get]
func (h *OAuth2Handler) Discover(c *gin.Context) {
	tenantID := h.resolveTenantID(c)

	_, err := h.TenantUse.GetTenant(c.Request.Context(), tenantID)
	if err != nil {
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
		},

		"response_modes_supported": []string{"query", "form_post"},

		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
		},

		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},

		"id_token_encryption_alg_values_supported": []string{"RSA-OAEP", "RSA-OAEP-256"},
		"id_token_encryption_enc_values_supported": []string{"A256GCM", "A128GCM"},

		"scopes_supported": []string{"openid", "offline_access", "profile", "email", "address", "phone"},

		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "none"},

		"claims_supported": []string{"sub", "iss", "tenant_id", "name", "email", "email_verified", "phone_number", "address", "auth_time"},

		"display_values_supported": []string{"page", "popup"},
		"ui_locales_supported":     []string{"en-US"},
	})
}
