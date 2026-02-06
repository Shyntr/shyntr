package router

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/api/handlers"
	"github.com/nevzatcirak/shyntr/internal/api/middleware"
	"github.com/nevzatcirak/shyntr/internal/core/auth"
	"gorm.io/gorm"
)

func SetupRoutes(db *gorm.DB, authProvider *auth.Provider, cfg *config.Config, km *auth.KeyManager) *gin.Engine {
	r := gin.New()

	r.Use(gin.Recovery())
	r.Use(middleware.RequestLogger())
	r.Use(middleware.SecurityHeaders())

	r.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.AllowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-CSRF-Token", "traceparent", "tracestate"},
		ExposeHeaders:    []string{"Content-Length", "traceparent", "tracestate"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.Use(middleware.CSRFMiddleware())

	healthHandler := handlers.NewHealthHandler(db)
	oauthHandler := handlers.NewOAuth2Handler(authProvider, db, km)
	loginHandler := handlers.NewLoginHandler(db)
	consentHandler := handlers.NewConsentHandler()

	r.GET("/health", healthHandler.Check)

	// Login
	r.GET("/login", loginHandler.ShowLogin)
	r.POST("/login", loginHandler.SubmitLogin)

	// Consent
	r.GET("/consent", consentHandler.ShowConsent)
	r.POST("/consent", consentHandler.SubmitConsent)

	// OIDC
	r.GET("/.well-known/openid-configuration", oauthHandler.Discover)
	r.GET("/.well-known/jwks.json", oauthHandler.Jwks)
	r.GET("/userinfo", oauthHandler.UserInfo)

	// OAuth2
	oauthGroup := r.Group("/oauth2")
	{
		oauthGroup.GET("/auth", oauthHandler.Authorize)
		oauthGroup.POST("/token", oauthHandler.Token)
		oauthGroup.POST("/revoke", oauthHandler.Revoke)
		oauthGroup.POST("/introspect", oauthHandler.Introspect)
	}

	return r
}
