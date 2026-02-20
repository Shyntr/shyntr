package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/api/handlers"
	"github.com/nevzatcirak/shyntr/internal/core/auth"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/internal/data/repository"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/hmac"
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func setupUserInfoAPI(t *testing.T) (*gin.Engine, *gorm.DB, *auth.Provider) {
	logger.InitLogger("info")

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}

	db.AutoMigrate(
		&models.SigningKey{},
		&models.LoginRequest{},
		&models.OAuth2Session{},
		&models.OAuth2Client{},
	)

	cfg := &config.Config{
		AppSecret: "12345678901234567890123456789012",
	}

	km := auth.NewKeyManager(db, cfg)
	_ = km.GetActivePrivateKey()

	provider := auth.NewProvider(db, []byte(cfg.AppSecret), "http://localhost:8080", km)
	handler := handlers.NewOAuth2Handler(provider, db, km, cfg)

	gin.SetMode(gin.TestMode)
	r := gin.New()

	r.GET("/t/:tenant_id/userinfo", handler.UserInfo)
	r.GET("/userinfo", handler.UserInfo)

	return r, db, provider
}

func TestUserInfo_Security_LeastPrivilege(t *testing.T) {
	r, db, _ := setupUserInfoAPI(t)
	defer db.Exec("DELETE FROM login_requests")
	defer db.Exec("DELETE FROM o_auth2_sessions")
	defer db.Exec("DELETE FROM o_auth2_clients")

	subject := "user-secure-123"
	clientID := "client-1"

	err := db.Create(&models.OAuth2Client{
		ID:       clientID,
		TenantID: "default",
		Name:     "Test Client",
	}).Error
	assert.NoError(t, err, "Failed to create test client")

	userContext := map[string]interface{}{
		"name":         "Jane Doe",
		"email":        "jane@example.com",
		"phone_number": "+1234567890",
		"address":      "123 Secret St.",
	}
	ctxBytes, _ := json.Marshal(userContext)

	err = db.Create(&models.LoginRequest{
		ID:            "login-req-1",
		Subject:       subject,
		TenantID:      "default",
		Context:       ctxBytes,
		Authenticated: true,
		UpdatedAt:     time.Now(),
	}).Error
	assert.NoError(t, err, "Failed to create mock login request")

	t.Run("Enforce Scope Restrictions on UserInfo", func(t *testing.T) {
		store := repository.NewSQLStore(db)

		hmacStrategy := &hmac.HMACStrategy{
			Config: &fosite.Config{
				GlobalSecret: []byte("12345678901234567890123456789012"),
			},
		}

		token, signature, err := hmacStrategy.Generate(context.Background())
		assert.NoError(t, err)

		session := &openid.DefaultSession{
			Subject: subject,
			Claims: &jwt.IDTokenClaims{
				Subject: subject,
				Extra:   userContext,
			},
			Headers: &jwt.Headers{},
			ExpiresAt: map[fosite.TokenType]time.Time{
				fosite.AccessToken: time.Now().Add(1 * time.Hour),
			},
		}

		fositeReq := fosite.NewAccessRequest(session)
		fositeReq.GrantScope("openid")
		fositeReq.GrantScope("email")
		fositeReq.Client = &fosite.DefaultClient{ID: clientID}

		err = store.CreateAccessTokenSession(context.Background(), signature, fositeReq)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var responseData map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &responseData)

		assert.Equal(t, subject, responseData["sub"])
		assert.Equal(t, "jane@example.com", responseData["email"])

		_, hasName := responseData["name"]
		_, hasPhone := responseData["phone_number"]
		_, hasAddress := responseData["address"]

		assert.False(t, hasName, "Name leaked without 'profile' scope!")
		assert.False(t, hasPhone, "Phone leaked without 'phone' scope!")
		assert.False(t, hasAddress, "Address leaked without 'address' scope!")
	})
}
