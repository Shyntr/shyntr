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
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-jose/go-jose/v4"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func setupJWKSAPI(t *testing.T) (*gin.Engine, *gorm.DB) {
	logger.InitLogger("info")

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}
	db.AutoMigrate(&models.CryptoKeyGORM{}, &models.OutboundPolicyGORM{})

	cfg := &config.Config{
		AppSecret: "12345678901234567890123456789012",
	}
	fositeConfig := &fosite.Config{
		AccessTokenLifespan:        1 * time.Hour,
		AuthorizeCodeLifespan:      10 * time.Minute,
		IDTokenLifespan:            1 * time.Hour,
		RefreshTokenLifespan:       30 * 24 * time.Hour, // 30 Days
		GlobalSecret:               []byte(cfg.AppSecret),
		IDTokenIssuer:              cfg.BaseIssuerURL,
		SendDebugMessagesToClients: true,
	}
	keyRepository := repository.NewCryptoKeyRepository(db)
	keyMgr := utils2.NewKeyManager(keyRepository, cfg)
	keyMgr.GetActivePrivateKey(context.Background(), "sig")
	requestRepository := repository.NewAuthRequestRepository(db)
	jtiRepository := repository.NewBlacklistedJTIRepository(db)
	tenantRepository := repository.NewTenantRepository(db)
	clientRepository := repository.NewOAuth2ClientRepository(db)
	sessionRepository := repository.NewOAuth2SessionRepository(db)
	connectionRepository := repository.NewOIDCConnectionRepository(db)
	scopeRepository := repository.NewScopeRepository(db)

	auditLogger := audit.NewAuditLogger(db)

	iam.NewFositeStore(db, clientRepository, jtiRepository)
	fositeSecretHasher := iam.NewFositeSecretHasher(fositeConfig)

	cache := utils2.NewJWKSCache()
	policyRepository := repository.NewOutboundPolicyRepository(db)
	outboundGuard := security.NewOutboundGuard(policyRepository, cfg.SkipTLSVerify)
	//UseCase
	scopeUseCase := usecase.NewScopeUseCase(scopeRepository, auditLogger)
	auth2ClientUseCase := usecase.NewOAuth2ClientUseCase(clientRepository, connectionRepository, tenantRepository, auditLogger, fositeSecretHasher, keyMgr, outboundGuard, cfg)
	authUseCase := usecase.NewAuthUseCase(requestRepository, auditLogger)
	tenantUseCase := usecase.NewTenantUseCase(tenantRepository, auditLogger, scopeRepository)
	connectionUseCase := usecase.NewOIDCConnectionUseCase(connectionRepository, auditLogger, scopeUseCase, outboundGuard)
	sessionUseCase := usecase.NewOAuth2SessionUseCase(sessionRepository, auditLogger)
	provider := utils2.NewProvider(db, fositeConfig, keyMgr, clientRepository, jtiRepository)

	handler := handlers.NewOAuth2Handler(provider, keyMgr, cfg, auth2ClientUseCase, authUseCase, sessionUseCase,
		connectionUseCase, tenantUseCase, scopeUseCase, cache)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/.well-known/jwks.json", handler.Jwks)

	return r, db
}

func TestJWKS_Security_NoPrivateKeyLeak(t *testing.T) {
	r, db := setupJWKSAPI(t)
	defer db.Exec("DELETE FROM signing_keys")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/.well-known/jwks.json", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var jwks jose.JSONWebKeySet
	err := json.Unmarshal(w.Body.Bytes(), &jwks)
	assert.NoError(t, err)

	assert.NotEmpty(t, jwks.Keys, "JWKS should contain at least one key")

	var rawJSON map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &rawJSON)

	keys := rawJSON["keys"].([]interface{})
	for _, keyInterface := range keys {
		keyMap := keyInterface.(map[string]interface{})

		assert.Contains(t, keyMap, "kty", "Key type (kty) must be present")
		assert.Contains(t, keyMap, "kid", "Key ID (kid) must be present")

		privateParams := []string{"d", "p", "q", "dp", "dq", "qi"}
		for _, param := range privateParams {
			_, exists := keyMap[param]
			assert.False(t, exists, "CRITICAL VULNERABILITY: Private key parameter '%s' leaked in JWKS!", param)
		}
	}
}
