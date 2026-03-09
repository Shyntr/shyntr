package handlers_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/lib/pq"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/adapters/audit"
	"github.com/nevzatcirak/shyntr/internal/adapters/http/handlers"
	"github.com/nevzatcirak/shyntr/internal/adapters/iam"
	"github.com/nevzatcirak/shyntr/internal/adapters/persistence/models"
	"github.com/nevzatcirak/shyntr/internal/adapters/persistence/repository"
	"github.com/nevzatcirak/shyntr/internal/application/usecase"
	utils2 "github.com/nevzatcirak/shyntr/internal/application/utils"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func setupConsentAPI(t *testing.T) (*gin.Engine, *gorm.DB) {
	logger.InitLogger("info")
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}
	db.AutoMigrate(
		&models.ConsentRequestGORM{},
		&models.AuditLogGORM{},
		&models.SigningKeyGORM{},
		&models.OAuth2ClientGORM{},
		&models.TenantGORM{},
	)

	cfg := &config.Config{
		AppSecret:     "12345678901234567890123456789012",
		BaseIssuerURL: "http://localhost:7496",
	}

	db.Create(&models.ConsentRequestGORM{
		ID:                "challenge-consent-123",
		ClientID:          "client-1",
		RequestedScope:    pq.StringArray{"openid", "profile", "email", "offline_access"},
		RequestedAudience: pq.StringArray{"https://api.example.com", "https://api.hacker.com"},
		Active:            true,
	})
	keyMgr := utils2.NewKeyManager(db, cfg)
	_ = keyMgr.GetActivePrivateKey()
	fositeConfig := &fosite.Config{
		AccessTokenLifespan:        1 * time.Hour,
		AuthorizeCodeLifespan:      10 * time.Minute,
		IDTokenLifespan:            1 * time.Hour,
		RefreshTokenLifespan:       30 * 24 * time.Hour,
		GlobalSecret:               []byte(cfg.AppSecret),
		IDTokenIssuer:              cfg.BaseIssuerURL,
		SendDebugMessagesToClients: true,
	}

	requestRepository := repository.NewAuthRequestRepository(db)
	tenantRepository := repository.NewTenantRepository(db)
	clientRepository := repository.NewOAuth2ClientRepository(db)
	connectionRepository := repository.NewOIDCConnectionRepository(db)
	scopeRepository := repository.NewScopeRepository(db)
	auditLogger := audit.NewAuditLogger(db)

	fositeSecretHasher := iam.NewFositeSecretHasher(fositeConfig)

	clientUseCase := usecase.NewOAuth2ClientUseCase(clientRepository, connectionRepository, tenantRepository, auditLogger, fositeSecretHasher, keyMgr, cfg)
	authUseCase := usecase.NewAuthUseCase(requestRepository, auditLogger)
	tenantUseCase := usecase.NewTenantUseCase(tenantRepository, auditLogger, scopeRepository)
	handler := handlers.NewAdminHandler(tenantUseCase, clientUseCase, authUseCase, cfg)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.PUT("/admin/consent/accept", handler.AcceptConsentRequest)
	r.PUT("/admin/consent/reject", handler.RejectConsentRequest)

	return r, db
}

func TestConsentAPI_LeastPrivilegeEnforcement(t *testing.T) {
	r, db := setupConsentAPI(t)
	defer db.Exec("DELETE FROM consent_requests")

	t.Run("Accept Consent with Full Payload Validation", func(t *testing.T) {
		payload := []byte(`{
			"grant_scope": ["openid", "email"],
			"grant_audience": ["https://api.example.com"],
			"remember": true,
			"remember_for": 3600
		}`)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/admin/consent/accept?consent_challenge=challenge-consent-123", bytes.NewBuffer(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var consent models.ConsentRequestGORM
		db.First(&consent, "id = ?", "challenge-consent-123")

		assert.ElementsMatch(t, []string{"openid", "email"}, []string(consent.GrantedScope))
		assert.NotContains(t, consent.GrantedScope, "profile")

		assert.ElementsMatch(t, []string{"https://api.example.com"}, []string(consent.GrantedAudience))
		assert.NotContains(t, consent.GrantedAudience, "https://api.hacker.com")

		assert.True(t, consent.Remember, "Remember flag should be true")
		assert.Equal(t, 3600, consent.RememberFor, "RememberFor duration should be mapped correctly")
	})

	t.Run("Reject Consent Completely", func(t *testing.T) {
		db.Create(&models.ConsentRequestGORM{
			ID:             "challenge-reject-456",
			ClientID:       "client-1",
			RequestedScope: pq.StringArray{"openid"},
			Active:         true,
		})

		payload := []byte(`{
			"error": "access_denied",
			"error_description": "User denied the request"
		}`)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/admin/consent/reject?consent_challenge=challenge-reject-456", bytes.NewBuffer(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var consent models.ConsentRequestGORM
		db.First(&consent, "id = ?", "challenge-reject-456")

		assert.False(t, consent.Active)
	})
}
