package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-jose/go-jose/v3"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/api/handlers"
	"github.com/nevzatcirak/shyntr/internal/core/auth"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func setupJWKSAPI(t *testing.T) (*gin.Engine, *gorm.DB) {
	logger.InitLogger("info")

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}
	db.AutoMigrate(&models.SigningKey{})

	cfg := &config.Config{
		AppSecret: "12345678901234567890123456789012",
	}

	km := auth.NewKeyManager(db, cfg)
	_ = km.GetActivePrivateKey()

	provider := auth.NewProvider(db, []byte(cfg.AppSecret), "http://localhost", km)

	handler := handlers.NewOAuth2Handler(provider, db, km, cfg)

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
