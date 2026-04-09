package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/audit"
	"github.com/Shyntr/shyntr/internal/adapters/http/handlers"
	"github.com/Shyntr/shyntr/internal/adapters/iam"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/repository"
	"github.com/Shyntr/shyntr/internal/application/security"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	utils2 "github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupOAuth2HandlerWithDBForPKCETests(t *testing.T, db *gorm.DB) *handlers.OAuth2Handler {
	t.Helper()

	cfg := &config.Config{
		CookieSecure:    false,
		AppSecret:       "12345678901234567890123456789012",
		BaseIssuerURL:   "http://localhost:7496",
		DefaultTenantID: "default",
	}

	fositeConfig := &fosite.Config{
		AccessTokenLifespan:            time.Hour,
		AuthorizeCodeLifespan:          10 * time.Minute,
		IDTokenLifespan:                time.Hour,
		RefreshTokenLifespan:           30 * 24 * time.Hour,
		GlobalSecret:                   []byte(cfg.AppSecret),
		IDTokenIssuer:                  cfg.BaseIssuerURL,
		SendDebugMessagesToClients:     true,
		EnforcePKCE:                    true,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
	}

	requestRepository := repository.NewAuthRequestRepository(db)
	jtiRepository := repository.NewBlacklistedJTIRepository(db)
	tenantRepository := repository.NewTenantRepository(db)
	clientRepository := repository.NewOAuth2ClientRepository(db)
	sessionRepository := repository.NewOAuth2SessionRepository(db)
	connectionRepository := repository.NewOIDCConnectionRepository(db)
	scopeRepository := repository.NewScopeRepository(db)
	keyRepository := repository.NewCryptoKeyRepository(db)
	policyRepository := repository.NewOutboundPolicyRepository(db)

	auditLogger := audit.NewAuditLogger(db)

	iam.NewFositeStore(db, clientRepository, jtiRepository)
	fositeSecretHasher := iam.NewFositeSecretHasher(fositeConfig)

	keyMgr := utils2.NewKeyManager(keyRepository, cfg)
	_, _, err := keyMgr.GetActivePrivateKey(context.Background(), "sig")
	require.NoError(t, err)
	_, _, err = keyMgr.GetActivePrivateKey(context.Background(), "enc")
	require.NoError(t, err)

	jwksCache := utils2.NewJWKSCache()
	outboundGuard := security.NewOutboundGuard(policyRepository, cfg.SkipTLSVerify)

	scopeUseCase := usecase.NewScopeUseCase(scopeRepository, auditLogger)
	auth2ClientUseCase := usecase.NewOAuth2ClientUseCase(
		clientRepository,
		connectionRepository,
		tenantRepository,
		auditLogger,
		fositeSecretHasher,
		keyMgr,
		outboundGuard,
		cfg,
	)
	authUseCase := usecase.NewAuthUseCase(requestRepository, auditLogger)
	tenantUseCase := usecase.NewTenantUseCase(tenantRepository, auditLogger, scopeRepository)
	sessionUseCase := usecase.NewOAuth2SessionUseCase(sessionRepository, auditLogger)
	connectionUseCase := usecase.NewOIDCConnectionUseCase(connectionRepository, auditLogger, scopeUseCase, outboundGuard)

	provider := utils2.NewProvider(db, fositeConfig, keyMgr, clientRepository, jtiRepository)

	return handlers.NewOAuth2Handler(
		provider,
		keyMgr,
		cfg,
		auth2ClientUseCase,
		authUseCase,
		sessionUseCase,
		connectionUseCase,
		tenantUseCase,
		scopeUseCase,
		jwksCache,
	)
}

// TestOAuth2Handler_Authorize_RequiresPKCE verifies that a public client request
// without a code_challenge is rejected. Per RFC 7636 and Fosite behavior, when the
// redirect_uri is valid the error is delivered as a redirect (303 See Other) with
// error=invalid_request in the Location query string — not as a 400 body response.
func TestOAuth2Handler_Authorize_RequiresPKCE(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db := setupTestDB()
	require.NotNil(t, db)

	require.NoError(t, db.Create(&models.TenantGORM{
		ID:          "default",
		Name:        "default",
		DisplayName: "Default Tenant",
		Description: "Default tenant for PKCE tests",
	}).Error)

	require.NoError(t, db.Create(&models.OAuth2ClientGORM{
		ID:                      "public-client",
		TenantID:                "default",
		Name:                    "Public Client",
		Public:                  true,
		EnforcePKCE:             true,
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"http://localhost:3000/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ResponseModes:           []string{"query"},
		Scopes:                  []string{"openid", "profile", "email"},
	}).Error)

	handler := setupOAuth2HandlerWithDBForPKCETests(t, db)

	r := gin.New()
	r.GET("/oauth2/auth", handler.Authorize)

	reqURL := "/oauth2/auth?client_id=public-client&response_type=code&redirect_uri=" +
		url.QueryEscape("http://localhost:3000/callback") +
		"&scope=openid%20profile&state=test-state"

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Fosite redirects OAuth2 errors back to the redirect_uri when the client and
	// redirect_uri are valid. A 400 body response is only issued when the
	// redirect_uri itself cannot be trusted (e.g. unknown client, missing redirect_uri).
	assert.Equal(t, http.StatusSeeOther, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "error=invalid_request")
}

// TestOAuth2Handler_Authorize_RejectsCrossTenantClientUsage verifies that a client
// registered in tenant-a cannot be used in a tenant-b authorize request.
// Because the client does not exist in tenant-b's Fosite store, Fosite returns
// invalid_client (HTTP 401) directly — the redirect_uri cannot be trusted for an
// unknown client so no redirect is issued.
func TestOAuth2Handler_Authorize_RejectsCrossTenantClientUsage(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db := setupTestDB()
	require.NotNil(t, db)

	require.NoError(t, db.Create(&models.TenantGORM{
		ID:          "tenant-a",
		Name:        "tenant-a",
		DisplayName: "Tenant A",
		Description: "Tenant A",
	}).Error)

	require.NoError(t, db.Create(&models.TenantGORM{
		ID:          "tenant-b",
		Name:        "tenant-b",
		DisplayName: "Tenant B",
		Description: "Tenant B",
	}).Error)

	require.NoError(t, db.Create(&models.OAuth2ClientGORM{
		ID:                      "tenant-a-client",
		TenantID:                "tenant-a",
		Name:                    "Tenant A Client",
		Public:                  true,
		EnforcePKCE:             true,
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"http://localhost:3000/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ResponseModes:           []string{"query"},
		Scopes:                  []string{"openid", "profile"},
	}).Error)

	handler := setupOAuth2HandlerWithDBForPKCETests(t, db)

	r := gin.New()
	r.GET("/t/:tenant_id/oauth2/auth", handler.Authorize)

	reqURL := "/t/tenant-b/oauth2/auth?client_id=tenant-a-client&response_type=code&redirect_uri=" +
		url.QueryEscape("http://localhost:3000/callback") +
		"&scope=openid&state=test-state&code_challenge=test-challenge&code_challenge_method=S256"

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Fosite cannot trust the redirect_uri of an unknown client, so it writes the
	// error directly rather than redirecting. invalid_client is HTTP 401 per Fosite.
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_client")
}
