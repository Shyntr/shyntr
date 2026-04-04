package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/audit"
	"github.com/Shyntr/shyntr/internal/adapters/http/handlers"
	"github.com/Shyntr/shyntr/internal/adapters/http/middleware"
	"github.com/Shyntr/shyntr/internal/adapters/iam"
	"github.com/Shyntr/shyntr/internal/adapters/persistence"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/repository"
	"github.com/Shyntr/shyntr/internal/application/security"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	utils2 "github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func setupManagementAPI(t *testing.T) (*gin.Engine, *gorm.DB) {
	logger.InitLogger("info")
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}
	err = persistence.MigrateDB(db)
	if err != nil {
		t.Fatalf("failed to migrate database: %v", err)
	}
	db.Create(&models.TenantGORM{ID: "default", Name: "default"})
	db.Create(&models.TenantGORM{ID: "tenant-a", Name: "Tenant A"})
	db.Create(&models.TenantGORM{ID: "tenant-b", Name: "Tenant B"})

	db.Create(&models.OAuth2ClientGORM{ID: "client-a1", TenantID: "tenant-a", Name: "A1"})
	db.Create(&models.OAuth2ClientGORM{ID: "client-b1", TenantID: "tenant-b", Name: "B1"})
	cfg := &config.Config{
		AppSecret:     "12345678901234567890123456789012",
		BaseIssuerURL: "http://localhost:7496",
	}
	keyRepository := repository.NewCryptoKeyRepository(db)
	keyMgr := utils2.NewKeyManager(keyRepository, cfg)
	keyMgr.GetActivePrivateKey(context.Background(), "sig")

	fositeConfig := &fosite.Config{
		AccessTokenLifespan:        1 * time.Hour,
		AuthorizeCodeLifespan:      10 * time.Minute,
		IDTokenLifespan:            1 * time.Hour,
		RefreshTokenLifespan:       30 * 24 * time.Hour, // 30 Days
		GlobalSecret:               []byte(cfg.AppSecret),
		IDTokenIssuer:              cfg.BaseIssuerURL,
		SendDebugMessagesToClients: true,
	}

	policyRepository := repository.NewOutboundPolicyRepository(db)
	outboundGuard := security.NewOutboundGuard(policyRepository, cfg.SkipTLSVerify)
	requestRepository := repository.NewAuthRequestRepository(db)
	tenantRepository := repository.NewTenantRepository(db)
	clientRepository := repository.NewOAuth2ClientRepository(db)
	samlClientRepository := repository.NewSAMLClientRepository(db)
	sessionRepository := repository.NewOAuth2SessionRepository(db)
	connectionRepository := repository.NewOIDCConnectionRepository(db)
	samlConnectionRepository := repository.NewSAMLConnectionRepository(db)
	scopeRepository := repository.NewScopeRepository(db)
	auditLogger := audit.NewAuditLogger(db)

	fositeSecretHasher := iam.NewFositeSecretHasher(fositeConfig)

	auth2ClientUseCase := usecase.NewOAuth2ClientUseCase(clientRepository, connectionRepository, tenantRepository, auditLogger, fositeSecretHasher, keyMgr, outboundGuard, cfg)
	authUseCase := usecase.NewAuthUseCase(requestRepository, auditLogger)
	tenantUseCase := usecase.NewTenantUseCase(tenantRepository, auditLogger, scopeRepository)
	clientUseCase := usecase.NewSAMLClientUseCase(samlClientRepository, tenantRepository, auditLogger, outboundGuard)
	connectionUseCase := usecase.NewOIDCConnectionUseCase(connectionRepository, auditLogger, nil, outboundGuard)
	samlConnectionUseCase := usecase.NewSAMLConnectionUseCase(samlConnectionRepository, auditLogger, nil, outboundGuard)
	sessionUseCase := usecase.NewOAuth2SessionUseCase(sessionRepository, auditLogger)
	handler := handlers.NewManagementHandler(fositeConfig, auth2ClientUseCase, clientUseCase, samlConnectionUseCase, authUseCase, sessionUseCase, connectionUseCase, tenantUseCase, outboundGuard)

	gin.SetMode(gin.TestMode)
	r := gin.New()

	r.Use(middleware.ErrorHandlerMiddleware())

	r.DELETE("/tenants/:id", handler.DeleteTenant)
	r.GET("/clients/tenant/:tenant_id", handler.ListClientsByTenant)
	r.POST("/clients", handler.CreateClient)

	return r, db
}

func TestManagementAPI_Security(t *testing.T) {
	r, db := setupManagementAPI(t)

	defer db.Exec("DELETE FROM o_auth2_clients")
	defer db.Exec("DELETE FROM tenants")

	t.Run("Prevent Deletion of Default Tenant", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/tenants/default", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), `"code":"default_tenant_protected"`)
	})

	t.Run("Prevent Cross-Tenant Data Leakage (Client Listing)", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/clients/tenant/tenant-a", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var clients []model.OAuth2Client
		err := json.Unmarshal(w.Body.Bytes(), &clients)
		assert.NoError(t, err)

		assert.Len(t, clients, 1)
		assert.Equal(t, "client-a1", clients[0].ID)
		assert.Equal(t, "tenant-a", clients[0].TenantID)
	})

	t.Run("Enforce Tenant Binding on Resource Creation", func(t *testing.T) {
		payload := []byte(`{"id": "hacker-client", "tenant_id": "non-existent-tenant", "name": "Evil Client", "redirect_uris": ["http://localhost"], "grant_types": ["authorization_code"]}`)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/clients", bytes.NewBuffer(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), `"code":"resource_not_found"`)
	})
}
