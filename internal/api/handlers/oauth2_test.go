package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/lib/pq"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/api/handlers"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/consts"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func setupTestDB() *gorm.DB {
	logger.InitLogger("info")
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	db.AutoMigrate(
		&models.OAuth2Client{},
		&models.OAuth2Session{},
		&models.LoginRequest{},
		&models.ConsentRequest{},
		&models.SigningKey{},
	)
	return db
}

func TestOAuth2Handler_Logout(t *testing.T) {
	db := setupTestDB()
	cfg := &config.Config{CookieSecure: false}

	clientID := "test-client"
	logoutURI := "http://localhost:3000/bye"
	db.Create(&models.OAuth2Client{
		ID:                     clientID,
		TenantID:               "default",
		Secret:                 "secret",
		PostLogoutRedirectURIs: pq.StringArray{logoutURI},
	})

	handler := handlers.NewOAuth2Handler(nil, db, nil, cfg)
	gin.SetMode(gin.TestMode)

	t.Run("Valid Logout with Redirect", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("secret")}, nil)
		claims := jwt.Claims{
			Audience: []string{clientID},
		}
		rawToken, _ := jwt.Signed(signer).Claims(claims).CompactSerialize()

		req, _ := http.NewRequest("GET", "/oauth2/logout?post_logout_redirect_uri="+logoutURI+"&id_token_hint="+rawToken, nil)
		c.Request = req

		handler.Logout(c)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, logoutURI, w.Header().Get("Location"))
		cookie := w.Header().Get("Set-Cookie")
		assert.Contains(t, cookie, consts.SessionCookieName+"=;")
	})

	t.Run("Invalid Redirect URI (Not Whitelisted)", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		evilURI := "http://evil.com/logout"

		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("secret")}, nil)
		claims := jwt.Claims{Audience: []string{clientID}}
		rawToken, _ := jwt.Signed(signer).Claims(claims).CompactSerialize()

		req, _ := http.NewRequest("GET", "/oauth2/logout?post_logout_redirect_uri="+evilURI+"&id_token_hint="+rawToken, nil)
		c.Request = req

		handler.Logout(c)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEqual(t, evilURI, w.Header().Get("Location"))
		assert.Contains(t, w.Body.String(), "Redirect blocked")
	})
}
