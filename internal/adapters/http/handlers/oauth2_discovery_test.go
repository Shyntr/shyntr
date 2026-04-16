package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
)

func setupOAuth2HandlerForDiscoveryTests(t *testing.T) *handlers.OAuth2Handler {
	t.Helper()

	db := setupTestDB()
	require.NotNil(t, db)

	cfg := &config.Config{
		CookieSecure:    false,
		AppSecret:       "12345678901234567890123456789012",
		BaseIssuerURL:   "http://localhost:7496",
		DefaultTenantID: "default",
	}

	// Seed tenants explicitly because Discover checks tenant existence first.
	require.NoError(t, db.Create(&models.TenantGORM{
		ID:          "default",
		Name:        "default",
		DisplayName: "Default Tenant",
		Description: "Default tenant for tests",
	}).Error)

	require.NoError(t, db.Create(&models.TenantGORM{
		ID:          "tenant-alpha",
		Name:        "tenant-alpha",
		DisplayName: "Tenant Alpha",
		Description: "Tenant alpha for tests",
	}).Error)

	fositeConfig := &fosite.Config{
		AccessTokenLifespan:            time.Hour,
		AuthorizeCodeLifespan:          10 * time.Minute,
		IDTokenLifespan:                time.Hour,
		RefreshTokenLifespan:           30 * 24 * time.Hour,
		GlobalSecret:                   []byte(cfg.AppSecret),
		IDTokenIssuer:                  cfg.BaseIssuerURL,
		SendDebugMessagesToClients:     false,
		EnforcePKCE:                    true,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
	}

	auditLogger := audit.NewAuditLogger(db)

	clientRepository := repository.NewOAuth2ClientRepository(db)
	connectionRepository := repository.NewOIDCConnectionRepository(db)
	tenantRepository := repository.NewTenantRepository(db)
	authRequestRepository := repository.NewAuthRequestRepository(db)
	sessionRepository := repository.NewOAuth2SessionRepository(db)
	scopeRepository := repository.NewScopeRepository(db)
	jtiRepository := repository.NewBlacklistedJTIRepository(db)
	keyRepository := repository.NewCryptoKeyRepository(db)
	outboundPolicyRepository := repository.NewOutboundPolicyRepository(db)

	keyMgr := utils2.NewKeyManager(keyRepository, cfg)
	_, _, err := keyMgr.GetActivePrivateKey(context.Background(), "sig")
	require.NoError(t, err)
	_, _, err = keyMgr.GetActivePrivateKey(context.Background(), "enc")
	require.NoError(t, err)

	outboundGuard := security.NewOutboundGuard(outboundPolicyRepository, cfg.SkipTLSVerify)
	fositeSecretHasher := iam.NewFositeSecretHasher(fositeConfig)
	provider := utils2.NewProvider(db, fositeConfig, keyMgr, clientRepository, jtiRepository)

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
	authUseCase := usecase.NewAuthUseCase(authRequestRepository, auditLogger)
	sessionUseCase := usecase.NewOAuth2SessionUseCase(sessionRepository, auditLogger)
	tenantUseCase := usecase.NewTenantUseCase(tenantRepository, auditLogger, scopeRepository)
	scopeUseCase := usecase.NewScopeUseCase(scopeRepository, auditLogger)

	return handlers.NewOAuth2Handler(
		provider,
		keyMgr,
		cfg,
		auth2ClientUseCase,
		authUseCase,
		sessionUseCase,
		nil, // OIDCConnUse is not needed for discovery tests
		tenantUseCase,
		scopeUseCase,
		utils2.NewJWKSCache(),
	)
}

func TestOAuth2Handler_Discover_DefaultTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := setupOAuth2HandlerForDiscoveryTests(t)

	r := gin.New()
	r.GET("/.well-known/openid-configuration", handler.Discover)

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	require.NoError(t, err)

	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))

	assert.Equal(t, "http://localhost:7496", body["issuer"])
	assert.Equal(t, "http://localhost:7496/oauth2/auth", body["authorization_endpoint"])
	assert.Equal(t, "http://localhost:7496/oauth2/token", body["token_endpoint"])
	assert.Equal(t, "http://localhost:7496/.well-known/jwks.json", body["jwks_uri"])
	assert.Equal(t, "http://localhost:7496/userinfo", body["userinfo_endpoint"])
	assert.Equal(t, "http://localhost:7496/oauth2/logout", body["end_session_endpoint"])

	responseTypes, ok := body["response_types_supported"].([]interface{})
	require.True(t, ok)
	assert.Contains(t, responseTypes, "code")

	grantTypes, ok := body["grant_types_supported"].([]interface{})
	require.True(t, ok)
	assert.Contains(t, grantTypes, "authorization_code")
	assert.Contains(t, grantTypes, "refresh_token")
	assert.Contains(t, grantTypes, "client_credentials")

	tokenAuthMethods, ok := body["token_endpoint_auth_methods_supported"].([]interface{})
	require.True(t, ok)
	assert.Contains(t, tokenAuthMethods, "client_secret_basic")
	assert.Contains(t, tokenAuthMethods, "client_secret_post")
	assert.Contains(t, tokenAuthMethods, "private_key_jwt")
	assert.Contains(t, tokenAuthMethods, "none")
}

func TestOAuth2Handler_Discover_TenantScopedIssuer(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := setupOAuth2HandlerForDiscoveryTests(t)

	r := gin.New()
	r.GET("/t/:tenant_id/.well-known/openid-configuration", handler.Discover)

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/t/tenant-alpha/.well-known/openid-configuration", nil)
	require.NoError(t, err)

	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))

	expectedIssuer := "http://localhost:7496/t/tenant-alpha"

	assert.Equal(t, expectedIssuer, body["issuer"])
	assert.Equal(t, expectedIssuer+"/oauth2/auth", body["authorization_endpoint"])
	assert.Equal(t, expectedIssuer+"/oauth2/token", body["token_endpoint"])
	assert.Equal(t, expectedIssuer+"/.well-known/jwks.json", body["jwks_uri"])
	assert.Equal(t, expectedIssuer+"/userinfo", body["userinfo_endpoint"])
	assert.Equal(t, expectedIssuer+"/oauth2/logout", body["end_session_endpoint"])
}

func TestOAuth2Handler_Discover_UnknownTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := setupOAuth2HandlerForDiscoveryTests(t)

	r := gin.New()
	r.GET("/t/:tenant_id/.well-known/openid-configuration", handler.Discover)

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/t/does-not-exist/.well-known/openid-configuration", nil)
	require.NoError(t, err)

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_tenant")
}
