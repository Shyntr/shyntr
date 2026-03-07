package handlers_test

import (
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
	"github.com/nevzatcirak/shyntr/internal/adapters/audit"
	"github.com/nevzatcirak/shyntr/internal/adapters/http/handlers"
	"github.com/nevzatcirak/shyntr/internal/adapters/iam"
	"github.com/nevzatcirak/shyntr/internal/adapters/persistence/models"
	"github.com/nevzatcirak/shyntr/internal/adapters/persistence/repository"
	"github.com/nevzatcirak/shyntr/internal/application/usecase"
	utils2 "github.com/nevzatcirak/shyntr/internal/application/utils"
	"github.com/nevzatcirak/shyntr/pkg/consts"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/ory/fosite"
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
		&models.OAuth2ClientGORM{},
		&models.OAuth2SessionGORM{},
		&models.LoginRequestGORM{},
		&models.ConsentRequestGORM{},
		&models.AuditLogGORM{},
		&models.SigningKeyGORM{},
	)
	return db
}

func TestOAuth2Handler_Logout(t *testing.T) {
	db := setupTestDB()
	cfg := &config.Config{
		CookieSecure:  false,
		AppSecret:     "12345678901234567890123456789012",
		BaseIssuerURL: "http://localhost:7496",
	}

	clientID := "test-client"
	logoutURI := "http://localhost:3000/bye"
	db.Create(&models.OAuth2ClientGORM{
		ID:                     clientID,
		TenantID:               "default",
		Secret:                 "secret",
		PostLogoutRedirectURIs: pq.StringArray{logoutURI},
	})
	keyMgr := utils2.NewKeyManager(db, cfg)
	_ = keyMgr.GetActivePrivateKey()

	fositeConfig := &fosite.Config{
		AccessTokenLifespan:        1 * time.Hour,
		AuthorizeCodeLifespan:      10 * time.Minute,
		IDTokenLifespan:            1 * time.Hour,
		RefreshTokenLifespan:       30 * 24 * time.Hour, // 30 Days
		GlobalSecret:               []byte(cfg.AppSecret),
		IDTokenIssuer:              cfg.BaseIssuerURL,
		SendDebugMessagesToClients: true,
	}

	//Repository
	requestRepository := repository.NewAuthRequestRepository(db)
	jtiRepository := repository.NewBlacklistedJTIRepository(db)
	tenantRepository := repository.NewTenantRepository(db)
	clientRepository := repository.NewOAuth2ClientRepository(db)
	sessionRepository := repository.NewOAuth2SessionRepository(db)
	connectionRepository := repository.NewOIDCConnectionRepository(db)

	auditLogger := audit.NewAuditLogger(db)

	iam.NewFositeStore(db, clientRepository, jtiRepository)
	fositeSecretHasher := iam.NewFositeSecretHasher(fositeConfig.ClientSecretsHasher)

	//UseCase
	auth2ClientUseCase := usecase.NewOAuth2ClientUseCase(clientRepository, connectionRepository, tenantRepository, auditLogger, fositeSecretHasher, keyMgr, cfg)
	authUseCase := usecase.NewAuthUseCase(requestRepository, auditLogger)
	tenantUseCase := usecase.NewTenantUseCase(tenantRepository, auditLogger)
	connectionUseCase := usecase.NewOIDCConnectionUseCase(connectionRepository, auditLogger)
	sessionUseCase := usecase.NewOAuth2SessionUseCase(sessionRepository, auditLogger)
	provider := utils2.NewProvider(db, fositeConfig, keyMgr, clientRepository, jtiRepository)
	handler := handlers.NewOAuth2Handler(provider, keyMgr, cfg, auth2ClientUseCase, authUseCase, auditLogger, sessionUseCase,
		connectionUseCase, tenantUseCase)
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
