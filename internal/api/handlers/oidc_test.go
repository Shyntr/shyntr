package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/api/handlers"
	"github.com/nevzatcirak/shyntr/internal/core/mapper"
	"github.com/nevzatcirak/shyntr/internal/core/oidc"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/internal/data/repository"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func setupOIDCAPI(t *testing.T) (*gin.Engine, *gorm.DB) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}

	db.AutoMigrate(&models.OIDCConnection{}, &models.LoginRequest{})

	cfg := &config.Config{
		AppSecret: "12345678901234567890123456789012",
	}

	repo := repository.NewOIDCRepository(db)
	service := oidc.NewClientService(repo, cfg)
	attrMapper := mapper.New()
	handler := handlers.NewOIDCHandler(service, attrMapper, db)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/t/:tenant_id/oidc/callback", handler.Callback)

	return r, db
}

func TestOIDCAPI_StateProtection(t *testing.T) {
	r, db := setupOIDCAPI(t)
	defer db.Exec("DELETE FROM oidc_connections")
	defer db.Exec("DELETE FROM login_requests")

	t.Run("Reject Missing State Parameter", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/t/default/oidc/callback?code=auth-code-123", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_callback_params")
	})

	t.Run("Reject Manipulated or Unencrypted State", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/t/default/oidc/callback?code=auth-code-123&state=hacker-forged-state", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_state_token")
	})
}
