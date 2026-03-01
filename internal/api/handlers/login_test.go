package handlers_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/api/handlers"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func setupLoginAPI(t *testing.T) (*gin.Engine, *gorm.DB) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}
	db.AutoMigrate(&models.LoginRequest{})

	db.Create(&models.LoginRequest{
		ID:       "challenge-default",
		TenantID: "default",
		Active:   true,
	})
	db.Create(&models.LoginRequest{
		ID:       "challenge-custom",
		TenantID: "tenant-x",
		Active:   true,
	})

	cfg := &config.Config{CookieSecure: false}
	handler := handlers.NewLoginHandler(cfg, db)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/auth/login", handler.SubmitLogin)

	return r, db
}

func TestLoginAPI_ZeroTrustBoundary(t *testing.T) {
	r, db := setupLoginAPI(t)
	defer db.Exec("DELETE FROM login_requests")

	t.Run("Prevent Local Auth for Custom Tenants", func(t *testing.T) {
		payload := []byte(`{"login_challenge": "challenge-custom", "username": "admin", "password": "password"}`)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "local_login_disabled")
	})

	t.Run("Allow Local Auth for Default Tenant", func(t *testing.T) {
		payload := []byte(`{"login_challenge": "challenge-default", "username": "admin", "password": "password"}`)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "redirect_to")
	})
}
