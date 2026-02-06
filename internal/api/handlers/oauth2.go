package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/internal/core/auth"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/consts"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type OAuth2Handler struct {
	Provider *auth.Provider
	DB       *gorm.DB
	KeyMgr   *auth.KeyManager
}

func NewOAuth2Handler(p *auth.Provider, db *gorm.DB, km *auth.KeyManager) *OAuth2Handler {
	return &OAuth2Handler{Provider: p, DB: db, KeyMgr: km}
}

// Helper to get issuer for the current tenant
func (h *OAuth2Handler) getIssuer(c *gin.Context) string {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		// Fallback or error? For now, fallback to base
		return strings.TrimRight(h.Provider.Config.IDTokenIssuer, "/")
	}
	base := strings.TrimRight(h.Provider.Config.IDTokenIssuer, "/")
	return fmt.Sprintf("%s/t/%s", base, tenantID)
}

func (h *OAuth2Handler) Authorize(c *gin.Context) {
	ctx := c.Request.Context()

	// Fosite Authorize Request handling
	ar, err := h.Provider.Fosite.NewAuthorizeRequest(ctx, c.Request)
	if err != nil {
		h.Provider.Fosite.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	// VALIDATE TENANT: The client MUST belong to the tenant in the URL
	tenantID := c.Param("tenant_id")
	clientID := ar.GetClient().GetID()

	var client models.OAuth2Client
	if err := h.DB.First(&client, "id = ? AND tenant_id = ?", clientID, tenantID).Error; err != nil {
		// Client does not exist in this tenant context
		logger.Log.Warn("Client/Tenant mismatch or not found",
			zap.String("client_id", clientID),
			zap.String("tenant_id", tenantID))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "client not found in this tenant"})
		return
	}

	// BROKER FLOW:
	// Instead of checking cookie, we redirect to External Login UI with a challenge.
	// For MVP simplicity (as requested), we are keeping internal DB check but
	// structurally preparing for the split.
	//
	// TODO: Replace this cookie check with "Login Challenge" generation and redirect to ExternalLoginURL.

	userID := ""
	cookie, err := c.Cookie(consts.SessionCookieName)
	if err == nil && cookie != "" {
		userID = cookie
	}

	if userID == "" {
		// Redirect to our "External" Login UI (which might be internal routes for now)
		// We pass the tenant_id so the UI knows where to post back or which look & feel to load
		loginURL := fmt.Sprintf("/auth/login?return_to=%s&tenant_id=%s", c.Request.URL.String(), tenantID)
		c.Redirect(http.StatusFound, loginURL)
		return
	}

	// Consent Check logic...
	if !client.SkipConsent {
		if c.Query("consent_verifier") != "approved" {
			consentURL := fmt.Sprintf("/auth/consent?client_id=%s&scopes=%s&return_to=%s&tenant_id=%s",
				clientID, strings.Join(ar.GetRequestedScopes(), " "), c.Request.URL.String(), tenantID)
			c.Redirect(http.StatusFound, consentURL)
			return
		}
	}

	// Construct Session with Dynamic Issuer
	issuer := h.getIssuer(c)

	session := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      issuer, // Dynamic Issuer
			Subject:     userID,
			Audience:    ar.GetRequestedAudience(),
			ExpiresAt:   time.Now().Add(h.Provider.Config.IDTokenLifespan),
			IssuedAt:    time.Now(),
			RequestedAt: time.Now(),
			AuthTime:    time.Now(),
		},
		Headers: &jwt.Headers{
			Extra: map[string]interface{}{
				"kid": consts.SigningKeyID,
			},
		},
		Subject: userID,
	}

	// Enrich claims
	var user models.User
	if err := h.DB.First(&user, "id = ?", userID).Error; err == nil {
		session.Claims.Add("name", user.FirstName+" "+user.LastName)
		session.Claims.Add("email", user.Email)
		session.Claims.Add("email_verified", true)
		session.Claims.Add("tenant_id", tenantID) // Include tenant in token
	}

	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}
	for _, audience := range ar.GetRequestedAudience() {
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

	// Note: You might want to validate Tenant match here too if strict isolation is needed at Token level.

	response, err := h.Provider.Fosite.NewAccessResponse(ctx, ar)
	if err != nil {
		h.Provider.Fosite.WriteAccessError(ctx, c.Writer, ar, err)
		return
	}

	h.Provider.Fosite.WriteAccessResponse(ctx, c.Writer, ar, response)
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

	c.JSON(200, gin.H{
		"sub":            user.ID,
		"email":          user.Email,
		"name":           user.FirstName + " " + user.LastName,
		"email_verified": true,
	})
}

func (h *OAuth2Handler) Jwks(c *gin.Context) {
	privKey := h.KeyMgr.GetActivePrivateKey()
	jwks := auth.GeneratePublicJWKS(privKey)
	c.JSON(200, jwks)
}

func (h *OAuth2Handler) Discover(c *gin.Context) {
	issuer := h.getIssuer(c)

	c.JSON(200, gin.H{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth2/auth",
		"token_endpoint":                        issuer + "/oauth2/token",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"revocation_endpoint":                   issuer + "/oauth2/revoke",
		"introspection_endpoint":                issuer + "/oauth2/introspect",
		"response_types_supported":              []string{"code", "token", "id_token", "code id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "offline", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "iss", "name", "email", "email_verified", "tenant_id"},
	})
}
