package router

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/api/handlers"
	"github.com/nevzatcirak/shyntr/internal/api/middleware"
	"github.com/nevzatcirak/shyntr/internal/core/auth"
	"github.com/nevzatcirak/shyntr/internal/core/mapper"
	"github.com/nevzatcirak/shyntr/internal/core/oidc"
	"github.com/nevzatcirak/shyntr/internal/core/saml"
	"github.com/nevzatcirak/shyntr/internal/data/repository"
	"gorm.io/gorm"
)

func SetupRouters(db *gorm.DB, authProvider *auth.Provider, cfg *config.Config, km *auth.KeyManager) (*gin.Engine, *gin.Engine) {
	samlRepo := repository.NewSAMLRepository(db)
	oidcRepo := repository.NewOIDCRepository(db)

	samlService := saml.NewService(samlRepo, km, cfg)
	oidcService := oidc.NewClientService(oidcRepo, cfg)

	attrMapper := mapper.New()

	// Handlers
	healthHandler := handlers.NewHealthHandler(db)
	oauthHandler := handlers.NewOAuth2Handler(authProvider, db, km, cfg)
	loginHandler := handlers.NewLoginHandler(db)
	consentHandler := handlers.NewConsentHandler()
	adminHandler := handlers.NewAdminHandler(db, cfg)
	mgmtHandler := handlers.NewManagementHandler(db)

	samlHandler := handlers.NewSAMLHandler(samlService, attrMapper, db)
	oidcHandler := handlers.NewOIDCHandler(oidcService, attrMapper, db)

	public := gin.New()
	public.Use(gin.Recovery())
	public.Use(middleware.RequestLogger())
	public.Use(middleware.SecurityHeaders())

	public.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.AllowedOrigins,
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	public.Use(middleware.CSRFMiddleware())

	// Public Routes
	public.GET("/health", healthHandler.Check)

	// Discovery & JWKS
	public.GET("/.well-known/openid-configuration", oauthHandler.Discover)
	public.GET("/.well-known/jwks.json", oauthHandler.Jwks)
	public.GET("/userinfo", oauthHandler.UserInfo)

	// Authentication UI Redirects (User facing)
	uiGroup := public.Group("/auth")
	{
		uiGroup.GET("/login", loginHandler.ShowLogin)
		uiGroup.POST("/login", loginHandler.SubmitLogin)
		uiGroup.GET("/methods", loginHandler.GetLoginMethods)
		uiGroup.GET("/consent", consentHandler.ShowConsent)
		uiGroup.POST("/consent", consentHandler.SubmitConsent)
	}

	// SAML Routes
	rootSamlGroup := public.Group("/saml")
	{
		rootSamlGroup.GET("/sp/metadata", samlHandler.SPMetadata)
		rootSamlGroup.POST("/sp/acs", samlHandler.ACS)
		rootSamlGroup.GET("/idp/metadata", samlHandler.IDPMetadata)
		rootSamlGroup.GET("/login/:connection_id", samlHandler.Login)
		rootSamlGroup.GET("/idp/sso", samlHandler.IDPSSO)
		rootSamlGroup.POST("/idp/sso", samlHandler.IDPSSO)
	}

	// OAuth2 Routes
	oauthGroup := public.Group("/oauth2")
	{
		oauthGroup.GET("/auth", oauthHandler.Authorize)
		oauthGroup.POST("/token", oauthHandler.Token)
		oauthGroup.POST("/revoke", oauthHandler.Revoke)
		oauthGroup.POST("/introspect", oauthHandler.Introspect)
		oauthGroup.GET("/logout", oauthHandler.Logout)
	}

	// Tenant Routes
	tenantGroup := public.Group("/t/:tenant_id")
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
			samlGroup.GET("/idp/sso", samlHandler.IDPSSO)
			samlGroup.POST("/idp/sso", samlHandler.IDPSSO)
		}

		oidcGroup := tenantGroup.Group("/oidc")
		{
			oidcGroup.GET("/login/:connection_id", oidcHandler.Login)
			oidcGroup.GET("/callback", oidcHandler.Callback)
		}
	}

	admin := gin.New()
	admin.Use(gin.Recovery())
	admin.Use(middleware.RequestLogger())
	admin.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.AdminAllowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Admin-Key"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	admin.GET("/health", healthHandler.Check)

	adminGroup := admin.Group("/admin")
	{
		adminGroup.GET("/login", adminHandler.GetLoginRequest)
		adminGroup.PUT("/login/accept", adminHandler.AcceptLoginRequest)
		adminGroup.PUT("/login/reject", adminHandler.RejectLoginRequest)

		adminGroup.GET("/consent", adminHandler.GetConsentRequest)
		adminGroup.PUT("/consent/accept", adminHandler.AcceptConsentRequest)
		adminGroup.PUT("/consent/reject", adminHandler.RejectConsentRequest)

		mgmtGroup := adminGroup.Group("/management")
		{
			// OAuth2 Clients
			mgmtGroup.GET("/clients", mgmtHandler.ListClients)
			mgmtGroup.POST("/clients", mgmtHandler.CreateClient)
			mgmtGroup.PUT("/clients/:id", mgmtHandler.UpdateClient)
			mgmtGroup.DELETE("/clients/:id", mgmtHandler.DeleteClient)

			// SAML Connections
			mgmtGroup.GET("/saml-connections", mgmtHandler.ListSAMLConnections)
			mgmtGroup.POST("/saml-connections", mgmtHandler.CreateSAMLConnection)
			mgmtGroup.PUT("/saml-connections/:id", mgmtHandler.UpdateSAMLConnection)
			mgmtGroup.DELETE("/saml-connections/:id", mgmtHandler.DeleteSAMLConnection)

			// OIDC Connections
			mgmtGroup.GET("/oidc-connections", mgmtHandler.ListOIDCConnections)
			mgmtGroup.POST("/oidc-connections", mgmtHandler.CreateOIDCConnection)
			mgmtGroup.PUT("/oidc-connections/:id", mgmtHandler.UpdateOIDCConnection)
			mgmtGroup.DELETE("/oidc-connections/:id", mgmtHandler.DeleteOIDCConnection)
		}
	}

	return public, admin
}
