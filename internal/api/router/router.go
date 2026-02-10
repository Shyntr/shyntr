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
	oauthHandler := handlers.NewOAuth2Handler(authProvider, db, km, cfg)
	loginHandler := handlers.NewLoginHandler(db)
	consentHandler := handlers.NewConsentHandler()
	adminHandler := handlers.NewAdminHandler(db, cfg)

	r.GET("/health", healthHandler.Check)
	r.GET("/.well-known/openid-configuration", oauthHandler.Discover)
	r.GET("/.well-known/jwks.json", oauthHandler.Jwks)
	r.GET("/userinfo", oauthHandler.UserInfo)

	rootOAuth := r.Group("/oauth2")
	{
		rootOAuth.GET("/auth", oauthHandler.Authorize)
		rootOAuth.POST("/token", oauthHandler.Token)
		rootOAuth.POST("/revoke", oauthHandler.Revoke)
		rootOAuth.POST("/introspect", oauthHandler.Introspect)
		rootOAuth.GET("/logout", oauthHandler.Logout)
	}

	uiGroup := r.Group("/auth")
	{
		uiGroup.GET("/login", loginHandler.ShowLogin)
		uiGroup.POST("/login", loginHandler.SubmitLogin)
		uiGroup.GET("/consent", consentHandler.ShowConsent)
		uiGroup.POST("/consent", consentHandler.SubmitConsent)
	}

	tenantGroup := r.Group("/t/:tenant_id")
	{
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
			oauthGroup.GET("/logout", oauthHandler.Logout)
		}
	}

	adminGroup := r.Group("/admin")
	{
		adminGroup.GET("/login", adminHandler.GetLoginRequest)
		adminGroup.PUT("/login/accept", adminHandler.AcceptLoginRequest)
		adminGroup.PUT("/login/reject", adminHandler.RejectLoginRequest)

		adminGroup.GET("/consent", adminHandler.GetConsentRequest)
		adminGroup.PUT("/consent/accept", adminHandler.AcceptConsentRequest)
		adminGroup.PUT("/consent/reject", adminHandler.RejectConsentRequest)
	}

	return r
}
