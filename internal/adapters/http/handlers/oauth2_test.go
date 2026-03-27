package handlers_test

import (
	"context"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/audit"
	"github.com/Shyntr/shyntr/internal/adapters/http/handlers"
	"github.com/Shyntr/shyntr/internal/adapters/iam"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/repository"
	"github.com/Shyntr/shyntr/internal/application/security"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	utils2 "github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/pkg/consts"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/lib/pq"
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
		&models.CryptoKeyGORM{},
		&models.OutboundPolicyGORM{},
	)
	return db
}

func generateMockIDToken(privateKey *rsa.PrivateKey, subject, audience string) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, nil)
	if err != nil {
		return "", err
	}

	cl := jwt.Claims{
		Subject:  subject,
		Issuer:   "http://test-issuer.local",
		Audience: jwt.Audience{audience},
		Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
	}

	return jwt.Signed(signer).Claims(cl).Serialize()
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
	keyRepository := repository.NewCryptoKeyRepository(db)
	keyMgr := utils2.NewKeyManager(keyRepository, cfg)
	activePrivKey, _, _ := keyMgr.GetActivePrivateKey(context.Background(), "sig")

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
	scopeRepository := repository.NewScopeRepository(db)

	auditLogger := audit.NewAuditLogger(db)

	iam.NewFositeStore(db, clientRepository, jtiRepository)
	fositeSecretHasher := iam.NewFositeSecretHasher(fositeConfig)

	jwksCache := utils2.NewJWKSCache()

	policyRepository := repository.NewOutboundPolicyRepository(db)
	outboundGuard := security.NewOutboundGuard(policyRepository, cfg.SkipTLSVerify)
	//UseCase
	scopeUseCase := usecase.NewScopeUseCase(scopeRepository, auditLogger)
	auth2ClientUseCase := usecase.NewOAuth2ClientUseCase(clientRepository, connectionRepository, tenantRepository, auditLogger, fositeSecretHasher, keyMgr, outboundGuard, cfg)
	authUseCase := usecase.NewAuthUseCase(requestRepository, auditLogger)
	tenantUseCase := usecase.NewTenantUseCase(tenantRepository, auditLogger, scopeRepository)
	connectionUseCase := usecase.NewOIDCConnectionUseCase(connectionRepository, auditLogger, scopeUseCase, outboundGuard)
	sessionUseCase := usecase.NewOAuth2SessionUseCase(sessionRepository, auditLogger)
	provider := utils2.NewProvider(db, fositeConfig, keyMgr, clientRepository, jtiRepository)
	handler := handlers.NewOAuth2Handler(provider, keyMgr, cfg, auth2ClientUseCase, authUseCase, sessionUseCase,
		connectionUseCase, tenantUseCase, scopeUseCase, jwksCache)
	gin.SetMode(gin.TestMode)

	t.Run("Valid Logout with Redirect", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		validIDToken, err := generateMockIDToken(activePrivKey, "user-123", clientID)
		assert.NoError(t, err)

		req, _ := http.NewRequest("GET", "/oauth2/logout?id_token_hint="+validIDToken+"&post_logout_redirect_uri=http://localhost:3000/bye&state=xyz", nil)
		c.Request = req
		req.AddCookie(&http.Cookie{Name: consts.SessionCookieName, Value: "user-123"})
		handler.Logout(c)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, logoutURI+"?state=xyz", w.Header().Get("Location"))
		cookie := w.Header().Get("Set-Cookie")
		assert.Contains(t, cookie, consts.SessionCookieName+"=;")
	})

	t.Run("Invalid Redirect URI (Not Whitelisted)", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		evilURI := "http://evil.com/logout"

		rawToken, err := generateMockIDToken(activePrivKey, "user-123", clientID)
		assert.NoError(t, err)

		req, _ := http.NewRequest("GET", "/oauth2/logout?post_logout_redirect_uri="+evilURI+"&id_token_hint="+rawToken, nil)
		c.Request = req

		handler.Logout(c)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEqual(t, evilURI, w.Header().Get("Location"))
		assert.Contains(t, w.Body.String(), "Redirect blocked")
	})
}
