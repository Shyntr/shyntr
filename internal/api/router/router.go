package router

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/api/handlers"
	"github.com/nevzatcirak/shyntr/internal/api/middleware"
	"github.com/nevzatcirak/shyntr/internal/core/auth"
	"github.com/nevzatcirak/shyntr/pkg/consts"
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
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-CSRF-Token", consts.HeaderTraceParent, consts.HeaderTraceState},
		ExposeHeaders:    []string{"Content-Length", consts.HeaderTraceParent, consts.HeaderTraceState},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.Use(middleware.CSRFMiddleware())

	// Handlers
	healthHandler := handlers.NewHealthHandler(db)
	oauthHandler := handlers.NewOAuth2Handler(authProvider, db, km)
	loginHandler := handlers.NewLoginHandler(db)
	consentHandler := handlers.NewConsentHandler()

	// 1. SYSTEM ROUTES
	r.GET("/health", healthHandler.Check)

	// 2. INTERNAL UI ROUTES (Simulating the External App)
	// These endpoints represent the separate "Identity UI" application.
	// In a real Broker setup, these would be hosted separately.
	uiGroup := r.Group("/auth")
	{
		uiGroup.GET("/login", loginHandler.ShowLogin)
		uiGroup.POST("/login", loginHandler.SubmitLogin)
		uiGroup.GET("/consent", consentHandler.ShowConsent)
		uiGroup.POST("/consent", consentHandler.SubmitConsent)
	}

	// 3. TENANT PROTOCOL ROUTES
	// All OIDC/OAuth2 interaction happens under a specific tenant context.
	tenantGroup := r.Group("/t/:tenant_id")
	{
		// OIDC Discovery (Dynamic based on tenant)
		tenantGroup.GET("/.well-known/openid-configuration", oauthHandler.Discover)
		tenantGroup.GET("/.well-known/jwks.json", oauthHandler.Jwks)
		tenantGroup.GET("/userinfo", oauthHandler.UserInfo)

		// OAuth2 Endpoints
		oauthGroup := tenantGroup.Group("/oauth2")
		{
			oauthGroup.GET("/auth", oauthHandler.Authorize)
			oauthGroup.POST("/token", oauthHandler.Token)
			oauthGroup.POST("/revoke", oauthHandler.Revoke)
			oauthGroup.POST("/introspect", oauthHandler.Introspect)
		}
	}

	// 4. ADMIN API (For the External UI to talk to Shyntr)
	// Placeholder for future endpoints like /admin/login/accept
	_ = r.Group("/admin")
	{
		// e.g., PUT /login/accept, PUT /consent/accept
	}

	return r
}
