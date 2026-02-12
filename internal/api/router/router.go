package router

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/api/handlers"
	"github.com/nevzatcirak/shyntr/internal/api/middleware"
	"github.com/nevzatcirak/shyntr/internal/core/auth"
	"github.com/nevzatcirak/shyntr/internal/core/oidc"
	"github.com/nevzatcirak/shyntr/internal/core/saml"
	"github.com/nevzatcirak/shyntr/internal/data/repository"
	"github.com/nevzatcirak/shyntr/pkg/consts"
	"gorm.io/gorm"
)

func SetupRoutes(db *gorm.DB, authProvider *auth.Provider, cfg *config.Config, km *auth.KeyManager) *gin.Engine {
	r := gin.New()

	r.Use(gin.Recovery())
	r.Use(middleware.RequestLogger())
	r.Use(middleware.SecurityHeaders())

	samlRepo := repository.NewSAMLRepository(db)
	oidcRepo := repository.NewOIDCRepository(db)

	// Services
	samlService := saml.NewService(samlRepo, km, cfg)
	oidcService := oidc.NewClientService(oidcRepo, cfg)

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
	samlHandler := handlers.NewSAMLHandler(samlService, db)
	oidcHandler := handlers.NewOIDCHandler(oidcService, db)

	r.GET("/health", healthHandler.Check)

	// External UI Routes (Test only)
	uiGroup := r.Group("/auth")
	{
		uiGroup.GET("/login", loginHandler.ShowLogin)
		uiGroup.POST("/login", loginHandler.SubmitLogin)
		uiGroup.GET("/consent", consentHandler.ShowConsent)
		uiGroup.POST("/consent", consentHandler.SubmitConsent)
	}

	// 1. Root / Default Tenant Routes
	r.GET("/.well-known/openid-configuration", oauthHandler.Discover)
	r.GET("/.well-known/jwks.json", oauthHandler.Jwks)
	r.GET("/userinfo", oauthHandler.UserInfo)

	rootSamlGroup := r.Group("/saml")
	{
		rootSamlGroup.GET("/sp/metadata", samlHandler.SPMetadata)
		rootSamlGroup.POST("/sp/acs", samlHandler.ACS)

		rootSamlGroup.GET("/idp/metadata", samlHandler.IDPMetadata)

		rootSamlGroup.GET("/login/:connection_id", samlHandler.Login)
		// IdP Routes
		rootSamlGroup.GET("/idp/sso", samlHandler.IDPSSO)
		rootSamlGroup.POST("/idp/sso", samlHandler.IDPSSO)
	}

	oauthGroup := r.Group("/oauth2")
	{
		oauthGroup.GET("/auth", oauthHandler.Authorize)
		oauthGroup.POST("/token", oauthHandler.Token)
		oauthGroup.POST("/revoke", oauthHandler.Revoke)
		oauthGroup.POST("/introspect", oauthHandler.Introspect)
		oauthGroup.GET("/logout", oauthHandler.Logout)
	}

	// 2. Explicit Tenant Routes
	tenantGroup := r.Group("/t/:tenant_id")
	{
		tenantGroup.GET("/.well-known/openid-configuration", oauthHandler.Discover)
		tenantGroup.GET("/.well-known/jwks.json", oauthHandler.Jwks)
		tenantGroup.GET("/userinfo", oauthHandler.UserInfo)

		tOAuthGroup := tenantGroup.Group("/oauth2")
		{
			tOAuthGroup.GET("/auth", oauthHandler.Authorize)
			tOAuthGroup.POST("/token", oauthHandler.Token)
			tOAuthGroup.POST("/revoke", oauthHandler.Revoke)
			tOAuthGroup.POST("/introspect", oauthHandler.Introspect)
			tOAuthGroup.GET("/logout", oauthHandler.Logout)
		}

		samlGroup := tenantGroup.Group("/saml")
		{
			samlGroup.GET("/sp/metadata", samlHandler.SPMetadata)
			samlGroup.POST("/sp/acs", samlHandler.ACS)
			samlGroup.GET("/idp/metadata", samlHandler.IDPMetadata)
			samlGroup.GET("/login/:connection_id", samlHandler.Login)
			// IdP Routes
			samlGroup.GET("/idp/sso", samlHandler.IDPSSO)
			samlGroup.POST("/idp/sso", samlHandler.IDPSSO)
		}

		oidcGroup := tenantGroup.Group("/oidc")
		{
			oidcGroup.GET("/login/:connection_id", oidcHandler.Login)
			oidcGroup.GET("/callback", oidcHandler.Callback)
		}
	}

	// Admin APIs (Internal use by External UI)
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
