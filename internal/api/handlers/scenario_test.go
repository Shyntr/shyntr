package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/lib/pq"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/api/router"
	"github.com/nevzatcirak/shyntr/internal/core/auth"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/internal/data/repository"
	"github.com/nevzatcirak/shyntr/pkg/consts"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupFullStack() (*gin.Engine, *gorm.DB, *auth.KeyManager) {
	logger.InitLogger()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	db.AutoMigrate(
		&models.User{},
		&models.OAuth2Client{},
		&models.OAuth2Session{},
		&models.LoginRequest{},
		&models.ConsentRequest{},
		&models.SigningKey{},
		&models.BlacklistedJTI{},
	)

	cfg := config.LoadConfig()
	cfg.CookieSecure = false
	cfg.AppSecret = "12345678901234567890123456789012"

	keyMgr := auth.NewKeyManager(db, cfg)

	provider := auth.NewProvider(db, []byte(cfg.AppSecret), "http://localhost:8080", keyMgr)

	r := router.SetupRoutes(db, provider, cfg, keyMgr)
	return r, db, keyMgr
}

func TestScenario_TenantIsolation(t *testing.T) {
	r, db, _ := setupFullStack()

	clientA := models.OAuth2Client{
		ID:           "client-tenant-a",
		TenantID:     "tenant-a",
		Secret:       "secret",
		RedirectURIs: pq.StringArray{"http://localhost/cb"},
		Scopes:       pq.StringArray{"openid"},
	}
	db.Create(&clientA)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/t/tenant-b/oauth2/auth?client_id=client-tenant-a&response_type=code&scope=openid&state=12345678", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "client not found in this tenant")
}

func TestScenario_StrictScopes(t *testing.T) {
	r, db, _ := setupFullStack()

	client := models.OAuth2Client{
		ID:           "limited-client",
		TenantID:     "default",
		RedirectURIs: pq.StringArray{"http://localhost/cb"},
		Scopes:       pq.StringArray{"openid"},
	}
	db.Create(&client)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/t/default/oauth2/auth?client_id=limited-client&response_type=code&scope=openid+admin&state=12345678", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "error=invalid_scope")
}

func TestScenario_OIDC_Prompts(t *testing.T) {
	r, db, _ := setupFullStack()

	client := models.OAuth2Client{
		ID:           "prompt-client",
		TenantID:     "default",
		RedirectURIs: pq.StringArray{"http://localhost/cb"},
		Scopes:       pq.StringArray{"openid"},
	}
	db.Create(&client)

	t.Run("Prompt None Without Session Fails", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/t/default/oauth2/auth?client_id=prompt-client&response_type=code&scope=openid&prompt=none&state=12345678", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusSeeOther, w.Code)
		location := w.Header().Get("Location")
		assert.Contains(t, location, "error=login_required")
	})

	t.Run("Prompt None With Session Succeeds", func(t *testing.T) {
		user := models.User{ID: "user-123", Email: "test@test.com", IsActive: true}
		db.Create(&user)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/t/default/oauth2/auth?client_id=prompt-client&response_type=code&scope=openid&prompt=none&state=12345678", nil)

		req.AddCookie(&http.Cookie{Name: consts.SessionCookieName, Value: "user-123"})

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		assert.NotContains(t, location, "error=login_required")
		assert.Contains(t, location, "login_challenge=")
	})
}

func TestScenario_SecureLogout(t *testing.T) {
	r, db, _ := setupFullStack()

	validRedirect := "http://trusted.com/bye"
	client := models.OAuth2Client{
		ID:                     "logout-client",
		TenantID:               "default",
		PostLogoutRedirectURIs: pq.StringArray{validRedirect},
	}
	db.Create(&client)

	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("secret")}, nil)
	claims := jwt.Claims{Audience: []string{"logout-client"}}
	validTokenHint, _ := jwt.Signed(signer).Claims(claims).CompactSerialize()

	t.Run("Blocks Open Redirect (Invalid URI)", func(t *testing.T) {
		w := httptest.NewRecorder()
		evilURI := "http://evil.com"

		req, _ := http.NewRequest("GET", "/t/default/oauth2/logout?post_logout_redirect_uri="+evilURI+"&id_token_hint="+validTokenHint, nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEqual(t, evilURI, w.Header().Get("Location"))
	})

	t.Run("Allows Valid Redirect", func(t *testing.T) {
		w := httptest.NewRecorder()

		req, _ := http.NewRequest("GET", "/t/default/oauth2/logout?post_logout_redirect_uri="+validRedirect+"&id_token_hint="+validTokenHint, nil)
		req.AddCookie(&http.Cookie{Name: consts.SessionCookieName, Value: "some-session"})

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, validRedirect, w.Header().Get("Location"))

		foundSessionDelete := false
		for _, cookie := range w.Result().Cookies() {
			if cookie.Name == consts.SessionCookieName && cookie.MaxAge < 0 {
				foundSessionDelete = true
				break
			}
		}
		assert.True(t, foundSessionDelete, "Session cookie should be deleted (MaxAge < 0)")
	})
}

func TestScenario_GracePeriod(t *testing.T) {
	_, db, _ := setupFullStack()
	repo := repository.NewSQLStore(db)
	ctx := context.Background()

	signature := "test-sig-123"
	reqID := "req-123"
	longExpiry := time.Now().Add(30 * 24 * time.Hour)

	session := models.OAuth2Session{
		Signature: signature,
		RequestID: reqID,
		ClientID:  "client-1",
		Type:      "refresh_token",
		Active:    true,
		ExpiresAt: longExpiry,
	}
	err := db.Create(&session).Error
	require.NoError(t, err)

	err = repo.RevokeRefreshTokenMaybeGracePeriod(ctx, reqID, signature)
	assert.NoError(t, err)

	var updatedSession models.OAuth2Session
	err = db.First(&updatedSession, "signature = ?", signature).Error
	assert.NoError(t, err)

	assert.True(t, updatedSession.ExpiresAt.Before(longExpiry), "Expiry should be shortened")
	assert.True(t, updatedSession.ExpiresAt.After(time.Now()), "Token should still be valid for grace period")

	timeLeft := time.Until(updatedSession.ExpiresAt)
	assert.True(t, timeLeft < 20*time.Second, "Grace period should be short (approx 15s)")
}
