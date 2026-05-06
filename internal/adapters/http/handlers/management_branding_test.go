package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/audit"
	"github.com/Shyntr/shyntr/internal/adapters/http/handlers"
	"github.com/Shyntr/shyntr/internal/adapters/http/middleware"
	"github.com/Shyntr/shyntr/internal/adapters/http/payload"
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
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupManagementBrandingAPI(t *testing.T) (*gin.Engine, *gorm.DB) {
	t.Helper()
	logger.InitLogger("info")

	dbPath := filepath.Join(t.TempDir(), fmt.Sprintf("%s.db", t.Name()))
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, sqlDB.Close())
	})
	require.NoError(t, persistence.MigrateDB(db))

	require.NoError(t, db.Create(&models.TenantGORM{ID: "default", Name: "default"}).Error)
	require.NoError(t, db.Create(&models.TenantGORM{ID: "tenant-a", Name: "Tenant A"}).Error)
	require.NoError(t, db.Create(&models.TenantGORM{ID: "tenant-b", Name: "Tenant B"}).Error)

	cfg := &config.Config{
		AppSecret:     "12345678901234567890123456789012",
		BaseIssuerURL: "http://localhost:7496",
	}
	keyRepository := repository.NewCryptoKeyRepository(db)
	keyMgr := utils2.NewKeyManager(keyRepository, cfg)
	keyMgr.GetActivePrivateKey(context.Background(), "sig")

	fositeConfig := &fosite.Config{
		AccessTokenLifespan:        time.Hour,
		AuthorizeCodeLifespan:      10 * time.Minute,
		IDTokenLifespan:            time.Hour,
		RefreshTokenLifespan:       30 * 24 * time.Hour,
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
	auditLogRepository := repository.NewAuditLogRepository(db)
	auditUseCase := usecase.NewAuditUseCase(auditLogRepository)
	healthRepository := repository.NewHealthRepository(db)
	healthUseCase := usecase.NewHealthUseCase(healthRepository, keyMgr)
	brandingRepository := repository.NewBrandingRepository(db)
	brandingUseCase := usecase.NewBrandingUseCase(brandingRepository)

	fositeSecretHasher := iam.NewFositeSecretHasher(fositeConfig)
	auth2ClientUseCase := usecase.NewOAuth2ClientUseCase(clientRepository, connectionRepository, tenantRepository, auditLogger, fositeSecretHasher, keyMgr, outboundGuard, cfg)
	authUseCase := usecase.NewAuthUseCase(requestRepository, auditLogger)
	tenantUseCase := usecase.NewTenantUseCase(tenantRepository, auditLogger, scopeRepository)
	clientUseCase := usecase.NewSAMLClientUseCase(samlClientRepository, tenantRepository, auditLogger, outboundGuard)
	connectionUseCase := usecase.NewOIDCConnectionUseCase(connectionRepository, auditLogger, nil, outboundGuard)
	samlConnectionUseCase := usecase.NewSAMLConnectionUseCase(samlConnectionRepository, auditLogger, nil, outboundGuard)
	sessionUseCase := usecase.NewOAuth2SessionUseCase(sessionRepository, auditLogger)

	handler := handlers.NewManagementHandler(fositeConfig, auth2ClientUseCase, clientUseCase, samlConnectionUseCase, authUseCase, sessionUseCase, connectionUseCase, nil, tenantUseCase, auditUseCase, healthUseCase, outboundGuard, brandingUseCase)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.ErrorHandlerMiddleware())
	r.GET("/admin/management/tenants/:id/branding", handler.GetBranding)
	r.PUT("/admin/management/tenants/:id/branding/draft", handler.UpdateBrandingDraft)
	r.POST("/admin/management/tenants/:id/branding/publish", handler.PublishBranding)
	r.POST("/admin/management/tenants/:id/branding/discard", handler.DiscardBranding)
	r.POST("/admin/management/tenants/:id/branding/reset", handler.ResetBranding)
	r.DELETE("/admin/management/tenants/:id", handler.DeleteTenant)

	return r, db
}

func defaultBrandingTheme() model.BrandingConfig { return model.DefaultBrandingConfig() }

func TestBranding_GetReturnsDefaultsWhenNoRow(t *testing.T) {
	r, _ := setupManagementBrandingAPI(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/management/tenants/tenant-a/branding", nil)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp payload.BrandingResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "tenant-a", resp.TenantID)
	assert.Equal(t, model.DefaultBrandingConfig().ThemeID, resp.Draft.ThemeID)
	assert.Equal(t, model.DefaultBrandingConfig().ThemeID, resp.Published.ThemeID)
	assert.False(t, resp.HasUnpublishedChanges)
}

func TestBranding_Get404ForUnknownTenant(t *testing.T) {
	r, _ := setupManagementBrandingAPI(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/management/tenants/no-such-tenant/branding", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestBranding_UpdateDraft(t *testing.T) {
	r, _ := setupManagementBrandingAPI(t)

	theme := defaultBrandingTheme()
	theme.ThemeID = "custom-theme"
	body, _ := json.Marshal(map[string]interface{}{"theme": theme})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/management/tenants/tenant-a/branding/draft", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp payload.BrandingResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "custom-theme", resp.Draft.ThemeID)
	// Draft differs from defaults → hasUnpublishedChanges must be true.
	assert.True(t, resp.HasUnpublishedChanges)
}

func TestBranding_UpdateDraft_RejectsInvalidColor(t *testing.T) {
	r, _ := setupManagementBrandingAPI(t)

	theme := defaultBrandingTheme()
	theme.Colors.Primary = "not-a-color"
	body, _ := json.Marshal(map[string]interface{}{"theme": theme})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/management/tenants/tenant-a/branding/draft", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBranding_UpdateDraft_RejectsInsecureLogoURL(t *testing.T) {
	r, _ := setupManagementBrandingAPI(t)

	theme := defaultBrandingTheme()
	theme.Widget.LogoURL = "http://example.com/logo.png"
	body, _ := json.Marshal(map[string]interface{}{"theme": theme})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/management/tenants/tenant-a/branding/draft", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBranding_Publish(t *testing.T) {
	r, _ := setupManagementBrandingAPI(t)

	// Update draft first.
	theme := defaultBrandingTheme()
	theme.ThemeID = "to-publish"
	body, _ := json.Marshal(map[string]interface{}{"theme": theme})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/management/tenants/tenant-a/branding/draft", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Publish.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/admin/management/tenants/tenant-a/branding/publish", nil)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp payload.BrandingResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "to-publish", resp.Published.ThemeID)
	assert.Equal(t, "to-publish", resp.Draft.ThemeID)
	assert.False(t, resp.HasUnpublishedChanges)
	assert.NotNil(t, resp.PublishedAt)
}

func TestBranding_Discard_WhenNeverPublished_ResetsToDefaults(t *testing.T) {
	r, _ := setupManagementBrandingAPI(t)

	// Set a custom draft.
	theme := defaultBrandingTheme()
	theme.ThemeID = "modified"
	body, _ := json.Marshal(map[string]interface{}{"theme": theme})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/management/tenants/tenant-a/branding/draft", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Discard without ever publishing.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/admin/management/tenants/tenant-a/branding/discard", nil)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp payload.BrandingResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, model.DefaultBrandingConfig().ThemeID, resp.Draft.ThemeID)
}

func TestBranding_Discard_WhenNoRowAtAll_ReturnsDefaults(t *testing.T) {
	r, _ := setupManagementBrandingAPI(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/management/tenants/tenant-a/branding/discard", nil)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp payload.BrandingResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, model.DefaultBrandingConfig().ThemeID, resp.Draft.ThemeID)
}

func TestBranding_Reset_Draft(t *testing.T) {
	r, _ := setupManagementBrandingAPI(t)

	// Publish a custom theme.
	theme := defaultBrandingTheme()
	theme.ThemeID = "published-theme"
	body, _ := json.Marshal(map[string]interface{}{"theme": theme})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/management/tenants/tenant-a/branding/draft", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/admin/management/tenants/tenant-a/branding/publish", nil)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Reset draft only.
	resetBody, _ := json.Marshal(map[string]string{"target": "draft"})
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/admin/management/tenants/tenant-a/branding/reset", bytes.NewReader(resetBody))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp payload.BrandingResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, model.DefaultBrandingConfig().ThemeID, resp.Draft.ThemeID)
	// Published must still hold "published-theme".
	assert.Equal(t, "published-theme", resp.Published.ThemeID)
}

func TestBranding_Reset_DraftAndPublished(t *testing.T) {
	r, _ := setupManagementBrandingAPI(t)

	// Publish a custom theme.
	theme := defaultBrandingTheme()
	theme.ThemeID = "published-theme"
	body, _ := json.Marshal(map[string]interface{}{"theme": theme})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/management/tenants/tenant-a/branding/draft", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/admin/management/tenants/tenant-a/branding/publish", nil)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Reset both.
	resetBody, _ := json.Marshal(map[string]string{"target": "draft_and_published"})
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/admin/management/tenants/tenant-a/branding/reset", bytes.NewReader(resetBody))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp payload.BrandingResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, model.DefaultBrandingConfig().ThemeID, resp.Draft.ThemeID)
	assert.Equal(t, model.DefaultBrandingConfig().ThemeID, resp.Published.ThemeID)
	assert.False(t, resp.HasUnpublishedChanges)
	assert.Nil(t, resp.PublishedAt)
}

func TestBranding_Reset_InvalidTarget(t *testing.T) {
	r, _ := setupManagementBrandingAPI(t)

	resetBody, _ := json.Marshal(map[string]string{"target": "invalid"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/management/tenants/tenant-a/branding/reset", bytes.NewReader(resetBody))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBranding_TenantIsolation_CrossTenant404(t *testing.T) {
	r, _ := setupManagementBrandingAPI(t)

	// Set draft for tenant-a.
	theme := defaultBrandingTheme()
	theme.ThemeID = "tenant-a-theme"
	body, _ := json.Marshal(map[string]interface{}{"theme": theme})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/management/tenants/tenant-a/branding/draft", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// tenant-b must not see tenant-a's config; it gets its own defaults.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/admin/management/tenants/tenant-b/branding", nil)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp payload.BrandingResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "tenant-b", resp.TenantID)
	assert.Equal(t, model.DefaultBrandingConfig().ThemeID, resp.Draft.ThemeID,
		"tenant-b must not see tenant-a's branding")
}

func TestBranding_TenantIsolation_UnknownTenantReturns404(t *testing.T) {
	r, _ := setupManagementBrandingAPI(t)

	for _, method := range []string{http.MethodGet, http.MethodPut} {
		w := httptest.NewRecorder()
		var body *bytes.Reader
		if method == http.MethodPut {
			b, _ := json.Marshal(map[string]interface{}{"theme": defaultBrandingTheme()})
			body = bytes.NewReader(b)
		} else {
			body = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, "/admin/management/tenants/ghost-tenant/branding/draft", body)
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code, "method=%s", method)
	}
}

func TestBranding_DeleteTenantRemovesBrandingRow(t *testing.T) {
	r, db := setupManagementBrandingAPI(t)

	// Set draft for tenant-a.
	theme := defaultBrandingTheme()
	body, _ := json.Marshal(map[string]interface{}{"theme": theme})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/management/tenants/tenant-a/branding/draft", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Verify the row exists.
	var count int64
	require.NoError(t, db.Model(&models.TenantBrandingGORM{}).Where("tenant_id = ?", "tenant-a").Count(&count).Error)
	assert.Equal(t, int64(1), count)

	// Delete the tenant.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/admin/management/tenants/tenant-a", nil)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Branding row must be gone.
	require.NoError(t, db.Model(&models.TenantBrandingGORM{}).Where("tenant_id = ?", "tenant-a").Count(&count).Error)
	assert.Equal(t, int64(0), count, "branding row must be deleted on tenant cascade delete")
}
