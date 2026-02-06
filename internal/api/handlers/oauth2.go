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
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
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

// Authorize handles the OAuth2 authorize endpoint.
func (h *OAuth2Handler) Authorize(c *gin.Context) {
	ctx := c.Request.Context()
	ar, err := h.Provider.Fosite.NewAuthorizeRequest(ctx, c.Request)
	if err != nil {
		h.Provider.Fosite.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	// 1. Session Check
	userID := ""
	cookie, err := c.Cookie(consts.SessionCookieName)
	if err == nil && cookie != "" {
		userID = cookie
	}

	if userID == "" {
		loginURL := "/login?return_to=" + c.Request.URL.String()
		c.Redirect(http.StatusFound, loginURL)
		return
	}

	// 2. Client Consent Check
	clientID := ar.GetClient().GetID()
	var client models.OAuth2Client
	if err := h.DB.First(&client, "id = ?", clientID).Error; err == nil {
		// If client is NOT trusted (SkipConsent=false) AND user hasn't explicitly consented recently
		// For MVP: We just check SkipConsent. If false, redirect to consent page.
		// NOTE: In a full implementation, we would check a "Consent" table here.
		if !client.SkipConsent {
			// Check if we came back from consent page with a flag (simplified)
			if c.Query("consent_verifier") != "approved" {
				consentURL := fmt.Sprintf("/consent?client_id=%s&scopes=%s&return_to=%s",
					clientID, strings.Join(ar.GetRequestedScopes(), " "), c.Request.URL.String())
				c.Redirect(http.StatusFound, consentURL)
				return
			}
		}
	}

	// 3. Create OIDC Session
	session := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      h.Provider.Config.IDTokenIssuer,
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

	var user models.User
	if err := h.DB.First(&user, "id = ?", userID).Error; err == nil {
		session.Claims.Add("name", user.FirstName+" "+user.LastName)
		session.Claims.Add("email", user.Email)
		session.Claims.Add("email_verified", true)
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

// Token handles the OAuth2 token endpoint.
func (h *OAuth2Handler) Token(c *gin.Context) {
	ctx := c.Request.Context()
	session := &openid.DefaultSession{}
	ar, err := h.Provider.Fosite.NewAccessRequest(ctx, c.Request, session)
	if err != nil {
		h.Provider.Fosite.WriteAccessError(ctx, c.Writer, ar, err)
		return
	}

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
		"given_name":     user.FirstName,
		"family_name":    user.LastName,
		"email_verified": true,
	})
}

// Jwks returns keys from KeyManager
func (h *OAuth2Handler) Jwks(c *gin.Context) {
	privKey := h.KeyMgr.GetActivePrivateKey()
	jwks := auth.GeneratePublicJWKS(privKey)
	c.JSON(200, jwks)
}

func (h *OAuth2Handler) Discover(c *gin.Context) {
	issuer := h.Provider.Config.IDTokenIssuer
	issuer = strings.TrimRight(issuer, "/")
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
		"claims_supported":                      []string{"sub", "iss", "name", "email", "email_verified"},
	})
}
