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

func SetupRoutes(db *gorm.DB, authProvider *auth.Provider, cfg *config.Config) *gin.Engine {
	r := gin.New() // Use New() instead of Default() to control middleware

	r.Use(gin.Recovery())

	r.Use(middleware.RequestLogger())

	r.Use(middleware.SecurityHeaders())

	r.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.AllowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-CSRF-Token", "X-Request-ID"},
		ExposeHeaders:    []string{"Content-Length", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// 5. CSRF Protection
	r.Use(middleware.CSRFMiddleware())

	healthHandler := handlers.NewHealthHandler(db)
	oauthHandler := handlers.NewOAuth2Handler(authProvider, db)
	loginHandler := handlers.NewLoginHandler(db)

	r.GET("/health", healthHandler.Check)

	// Login Routes
	r.GET("/login", loginHandler.ShowLogin)
	r.POST("/login", loginHandler.SubmitLogin)

	// OIDC Discovery & Keys
	r.GET("/.well-known/openid-configuration", oauthHandler.Discover)
	r.GET("/.well-known/jwks.json", oauthHandler.Jwks)

	// UserInfo
	r.GET("/userinfo", oauthHandler.UserInfo)

	// OAuth2 Group
	oauthGroup := r.Group("/oauth2")
	{
		oauthGroup.GET("/auth", oauthHandler.Authorize)
		oauthGroup.POST("/token", oauthHandler.Token)
		oauthGroup.POST("/revoke", oauthHandler.Revoke)
		oauthGroup.POST("/introspect", oauthHandler.Introspect)
	}

	return r
}
