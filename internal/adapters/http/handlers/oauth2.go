package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/lib/pq"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/application/usecase"
	utils2 "github.com/nevzatcirak/shyntr/internal/application/utils"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
	"github.com/nevzatcirak/shyntr/pkg/constants"
	"github.com/nevzatcirak/shyntr/pkg/consts"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/nevzatcirak/shyntr/pkg/utils"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	fositejwt "github.com/ory/fosite/token/jwt"
	"go.uber.org/zap"
)

type OAuth2Handler struct {
	Provider         *utils2.Provider
	KeyMgr           *utils2.KeyManager
	Config           *config.Config
	OAuth2ClientUse  usecase.OAuth2ClientUseCase
	OAuth2SessionUse usecase.OAuth2SessionUseCase
	AuthReq          usecase.AuthUseCase
	OIDCConnUse      usecase.OIDCConnectionUseCase
	TenantUse        usecase.TenantUseCase
	ScopeUse         usecase.ScopeUseCase
}

func NewOAuth2Handler(p *utils2.Provider, km *utils2.KeyManager, cfg *config.Config, OAuth2ClientUse usecase.OAuth2ClientUseCase,
	AuthReq usecase.AuthUseCase, OAuth2SessionUse usecase.OAuth2SessionUseCase, OIDCConnUse usecase.OIDCConnectionUseCase,
	TenantUse usecase.TenantUseCase, ScopeUse usecase.ScopeUseCase) *OAuth2Handler {
	return &OAuth2Handler{Provider: p, KeyMgr: km, Config: cfg, OAuth2ClientUse: OAuth2ClientUse, AuthReq: AuthReq,
		OAuth2SessionUse: OAuth2SessionUse, TenantUse: TenantUse, OIDCConnUse: OIDCConnUse, ScopeUse: ScopeUse}
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
	tenantID := c.Param(constants.ContextKeyTenantID)
	if tenantID == "" {
		return h.Config.DefaultTenantID
	}
	return tenantID
}

func (h *OAuth2Handler) getIssuer(c *gin.Context) string {
	tenantID := h.resolveTenantID(c)
	base := strings.TrimRight(h.Provider.Config.IDTokenIssuer, "/")
	if c.Param(constants.ContextKeyTenantID) == "" {
		return base
	}
	return fmt.Sprintf("%s/t/%s", base, tenantID)
}

func (h *OAuth2Handler) Authorize(c *gin.Context) {
	tenantID := h.resolveTenantID(c)

	ctx := context.WithValue(c.Request.Context(), constants.ContextKeyTenantID, tenantID)

	ar, err := h.Provider.Fosite.NewAuthorizeRequest(ctx, c.Request)
	if err != nil {
		h.Provider.Fosite.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	clientID := ar.GetClient().GetID()

	client, err := h.OAuth2ClientUse.GetClientByTenant(ctx, tenantID, clientID)
	if err != nil {
		logger.FromGin(c).Warn("Client/Tenant mismatch or not found", zap.String("client_id", clientID), zap.String(constants.ContextKeyTenantID, tenantID))
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
			logger.FromGin(c).Warn("Invalid or expired login verifier", zap.String("verifier", verifier))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_login_verifier"})
			return
		}

	} else if hasSession && !forceLogin {
		userID = sessionCookie
		lastLogin, lastLoginErr := h.AuthReq.GetAuthenticatedLoginRequestBySubject(ctx, userID)
		if lastLoginErr == nil {
			authTime = lastLogin.UpdatedAt
			isRemembered = lastLogin.Remember
			rememberForDuration = lastLogin.RememberFor
			if len(lastLogin.Context) > 0 {
				if err := json.Unmarshal(lastLogin.Context, &userContext); err != nil {
					logger.FromGin(c).Error("Failed to unmarshal SSO user context", zap.Error(err))
				}
			}
		}
	}

	if userID == "" || forceLogin {
		challengeID, err := utils.GenerateRandomHex(16)
		if err != nil {
			logger.FromGin(c).Error("Failed to generate challenge", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal_server_error"})
			return
		}

		request := entity.LoginRequest{
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
			logger.FromGin(c).Error("Failed to save login request", zap.Error(err))
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
			request := entity.ConsentRequest{
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
	session := entity.NewJWTSession(userID)
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

	session.Claims.Add(constants.ContextKeyTenantID, tenantID)
	session.JWTClaims.Extra[constants.ContextKeyTenantID] = tenantID

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

	response, err := h.Provider.Fosite.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		h.Provider.Fosite.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	h.OAuth2SessionUse.RecordAuthorization(ctx, ar.GetID(), clientID, c.ClientIP(), c.Request.UserAgent(), grantedScopes)
	h.Provider.Fosite.WriteAuthorizeResponse(ctx, c.Writer, ar, response)
}

func (h *OAuth2Handler) Token(c *gin.Context) {
	tenantID := h.resolveTenantID(c)

	ctx := context.WithValue(c.Request.Context(), constants.ContextKeyTenantID, tenantID)
	emptySession := entity.NewJWTSession("")
	ar, err := h.Provider.Fosite.NewAccessRequest(ctx, c.Request, emptySession)
	if err != nil {
		logger.LogFositeError(c, err, "Failed to create access request in TokenEndpoint")
		h.Provider.Fosite.WriteAccessError(ctx, c.Writer, ar, err)
		return
	}

	urlTenantID := h.resolveTenantID(c)
	dbClient, dbClientErr := h.OAuth2ClientUse.GetClient(ctx, ar.GetClient().GetID())
	if dbClientErr != nil {
		logger.FromGin(c).Warn("Tenant mismatch", zap.String("client_id", ar.GetClient().GetID()), zap.String(constants.ContextKeyTenantID, urlTenantID))
		h.Provider.Fosite.WriteAccessError(ctx, c.Writer, ar, fosite.ErrInvalidClient)
		return
	}

	if dbClient.TenantID != urlTenantID {
		logger.FromGin(c).Warn("Tenant mismatch", zap.String("client_id", ar.GetClient().GetID()), zap.String(constants.ContextKeyTenantID, urlTenantID))
		h.Provider.Fosite.WriteAccessError(ctx, c.Writer, ar, fosite.ErrInvalidClient)
		return
	}

	response, err := h.Provider.Fosite.NewAccessResponse(ctx, ar)
	if err != nil {
		logger.LogFositeError(c, err, "Failed to create access response in TokenEndpoint")
		h.Provider.Fosite.WriteAccessError(ctx, c.Writer, ar, err)
		return
	}
	h.OAuth2SessionUse.RecordTokenIssuance(ctx, ar.GetID(), ar.GetClient().GetID(), c.ClientIP(), c.Request.UserAgent(), ar.GetGrantedScopes())
	h.Provider.Fosite.WriteAccessResponse(ctx, c.Writer, ar, response)
}

func (h *OAuth2Handler) Logout(c *gin.Context) {
	tenantID := h.resolveTenantID(c)
	postLogoutRedirectURI := c.Query("post_logout_redirect_uri")
	idTokenHint := c.Query("id_token_hint")
	state := c.Query("state")

	var subject string
	var idTokenAudience string

	if idTokenHint != "" {
		token, err := jwt.ParseSigned(idTokenHint)
		if err == nil {
			_, cert := h.KeyMgr.GetActiveKeys()
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
	ctx := context.WithValue(c.Request.Context(), constants.ContextKeyTenantID, tenantID)
	if subject == "" {
		sessionCookie, _ := c.Cookie(consts.SessionCookieName)
		subject = sessionCookie
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
		err := h.OAuth2SessionUse.DeleteBySubject(ctx, subject, idTokenAudience)
		if err != nil {
			logger.LogFositeError(c, err, "Failed to delete session in TokenEndpoint")
		}
		h.OAuth2SessionUse.RecordLogout(ctx, subject, c.ClientIP(), c.Request.UserAgent(), idTokenHint != "")
	}

	var idpSource string
	if subject != "" {
		lastLogin, err := h.AuthReq.GetAuthenticatedLoginRequestBySubject(ctx, subject)
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

				tID := c.Param(constants.ContextKeyTenantID)
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

func (h *OAuth2Handler) UserInfo(c *gin.Context) {
	tenantID := h.resolveTenantID(c)
	token := fosite.AccessTokenFromRequest(c.Request)
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})
		return
	}

	session := entity.NewJWTSession("")
	_, accessRequest, err := h.Provider.Fosite.IntrospectToken(c.Request.Context(), token, fosite.AccessToken, session)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	sess, ok := accessRequest.GetSession().(*entity.JWTSession)
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

	c.JSON(http.StatusOK, safeClaims)
}

func (h *OAuth2Handler) Introspect(c *gin.Context) {
	tenantID := h.resolveTenantID(c)
	ctx := context.WithValue(c.Request.Context(), constants.ContextKeyTenantID, tenantID)
	session := entity.NewJWTSession("")
	ar, err := h.Provider.Fosite.NewIntrospectionRequest(ctx, c.Request, session)
	if err != nil {
		h.Provider.Fosite.WriteIntrospectionError(ctx, c.Writer, err)
		return
	}
	h.Provider.Fosite.WriteIntrospectionResponse(ctx, c.Writer, ar)
}

func (h *OAuth2Handler) Revoke(c *gin.Context) {
	tenantID := h.resolveTenantID(c)
	ctx := context.WithValue(c.Request.Context(), constants.ContextKeyTenantID, tenantID)

	err := h.Provider.Fosite.NewRevocationRequest(ctx, c.Request)
	h.OAuth2SessionUse.RecordRevocation(ctx, c.ClientIP(), c.Request.UserAgent(), err == nil)
	h.Provider.Fosite.WriteRevocationResponse(ctx, c.Writer, err)
}

func (h *OAuth2Handler) Jwks(c *gin.Context) {
	privKey := h.KeyMgr.GetActivePrivateKey()
	jwks := utils2.GeneratePublicJWKS(privKey)
	c.JSON(http.StatusOK, jwks)
}

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
