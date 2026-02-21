package handlers_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/lib/pq"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/api/handlers"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func setupConsentAPI(t *testing.T) (*gin.Engine, *gorm.DB) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}
	db.AutoMigrate(&models.ConsentRequest{})

	cfg := &config.Config{}

	db.Create(&models.ConsentRequest{
		ID:                "challenge-consent-123",
		ClientID:          "client-1",
		RequestedScope:    pq.StringArray{"openid", "profile", "email", "offline_access"},
		RequestedAudience: pq.StringArray{"https://api.example.com", "https://api.hacker.com"},
		Active:            true,
	})

	handler := handlers.NewAdminHandler(db, cfg)

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

		var consent models.ConsentRequest
		db.First(&consent, "id = ?", "challenge-consent-123")

		assert.ElementsMatch(t, []string{"openid", "email"}, []string(consent.GrantedScope))
		assert.NotContains(t, consent.GrantedScope, "profile")

		assert.ElementsMatch(t, []string{"https://api.example.com"}, []string(consent.GrantedAudience))
		assert.NotContains(t, consent.GrantedAudience, "https://api.hacker.com")

		assert.True(t, consent.Remember, "Remember flag should be true")
		assert.Equal(t, 3600, consent.RememberFor, "RememberFor duration should be mapped correctly")
	})

	t.Run("Reject Consent Completely", func(t *testing.T) {
		db.Create(&models.ConsentRequest{
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

		var consent models.ConsentRequest
		db.First(&consent, "id = ?", "challenge-reject-456")

		assert.False(t, consent.Active)
	})
}
