package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/internal/core/auth"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/ory/fosite"
	"gorm.io/gorm"
)

type OAuth2Handler struct {
	Provider *auth.Provider
	DB       *gorm.DB
}

func NewOAuth2Handler(p *auth.Provider, db *gorm.DB) *OAuth2Handler {
	return &OAuth2Handler{Provider: p, DB: db}
}

// Authorize handles the OAuth2 authorize endpoint.
func (h *OAuth2Handler) Authorize(c *gin.Context) {
	ctx := c.Request.Context()
	ar, err := h.Provider.Fosite.NewAuthorizeRequest(ctx, c.Request)
	if err != nil {
		h.Provider.Fosite.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	// Check for existing session cookie
	userID := ""
	cookie, err := c.Cookie("shyntr_session")
	if err == nil && cookie != "" {
		userID = cookie
	}

	// Redirect to Login if no valid session is found
	if userID == "" {
		loginURL := "/login?return_to=" + c.Request.URL.String()
		c.Redirect(http.StatusFound, loginURL)
		return
	}

	// Create Session with OIDC Claims
	session := &fosite.DefaultSession{
		Subject: userID,
		Claims: &fosite.JWTClaims{
			Issuer:    h.Provider.Config.IDTokenIssuer,
			Subject:   userID,
			Audience:  ar.GetRequestedAudience(),
			ExpiresAt: h.Provider.Config.IDTokenLifespan,
			IssuedAt:  time.Now(),
		},
		Headers: &fosite.Headers{
			Extra: map[string]interface{}{
				"kid": "shyntr-key-1",
			},
		},
	}

	// Fetch User Data to populate ID Token claims
	var user models.User
	if err := h.DB.First(&user, "id = ?", userID).Error; err == nil {
		session.Claims.Add("name", user.FirstName+" "+user.LastName)
		session.Claims.Add("email", user.Email)
		session.Claims.Add("email_verified", true)
	}

	// Grant requested scopes and audiences
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
	session := &fosite.DefaultSession{}
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

// Introspect handles token introspection.
func (h *OAuth2Handler) Introspect(c *gin.Context) {
	ctx := c.Request.Context()
	session := &fosite.DefaultSession{}
	ar, err := h.Provider.Fosite.NewIntrospectionRequest(ctx, c.Request, session)
	if err != nil {
		h.Provider.Fosite.WriteIntrospectionError(ctx, c.Writer, err)
		return
	}

	h.Provider.Fosite.WriteIntrospectionResponse(ctx, c.Writer, ar)
}

// Revoke handles token revocation.
func (h *OAuth2Handler) Revoke(c *gin.Context) {
	ctx := c.Request.Context()
	err := h.Provider.Fosite.NewRevocationRequest(ctx, c.Request)
	if err != nil {
		h.Provider.Fosite.WriteRevocationResponse(ctx, c.Writer, err)
		return
	}
	h.Provider.Fosite.WriteRevocationResponse(ctx, c.Writer, nil)
}

// UserInfo returns OIDC user details.
func (h *OAuth2Handler) UserInfo(c *gin.Context) {
	token := fosite.AccessTokenFromRequest(c.Request)
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})
		return
	}

	ctx := c.Request.Context()
	ar, err := h.Provider.Fosite.IntrospectToken(ctx, token, fosite.AccessToken, &fosite.DefaultSession{})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	session := ar.GetSession().(*fosite.DefaultSession)
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

// Jwks returns the JSON Web Key Set for OIDC discovery.
func (h *OAuth2Handler) Jwks(c *gin.Context) {
	privKey := auth.GetOrGenerateRSAPrivateKey("shyntr-signing-key.pem")
	jwks := auth.GeneratePublicJWKS(privKey)
	c.JSON(200, jwks)
}

// Discover returns the OpenID Connect configuration.
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
