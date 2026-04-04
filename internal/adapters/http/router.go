package http

import (
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/http/handlers"
	"github.com/Shyntr/shyntr/internal/adapters/http/middleware"
	"github.com/Shyntr/shyntr/internal/application/mapper"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/application/security"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	utils2 "github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	_ "github.com/Shyntr/shyntr/docs"
)

func SetupRouter(
	clientUseCase usecase.OAuth2ClientUseCase,
	authUseCase usecase.AuthUseCase,
	tenantUseCase usecase.TenantUseCase,
	auditUseCase usecase.AuditUseCase,
	samlClientUseCase usecase.SAMLClientUseCase,
	connectionUseCase usecase.OIDCConnectionUseCase,
	samlConnectionUseCase usecase.SAMLConnectionUseCase,
	managementUseCase usecase.ManagementUseCase,
	auth2SessionUseCase usecase.OAuth2SessionUseCase,
	webhookUseCase usecase.WebhookUseCase,
	samlBuilderUseCase usecase.SamlBuilderUseCase,
	healthUseCase usecase.HealthUseCase,
	scopeUseCase usecase.ScopeUseCase,
	outboundPolicyUseCase usecase.OutboundPolicyUseCase,
	outboundGuard port.OutboundGuard,
	fositeCfg *fosite.Config,
	cfg *config.Config,
	Provider *utils2.Provider,
	km utils2.KeyManager,
	federationState security.FederationStateProvider,
) (*gin.Engine, *gin.Engine) {
	attrMapper := mapper.New()

	jwksCache := utils2.NewJWKSCache()

	// Handlers
	adminHandler := handlers.NewAdminHandler(tenantUseCase, clientUseCase, authUseCase, cfg)
	healthHandler := handlers.NewHealthHandler(healthUseCase)
	loginHandler := handlers.NewLoginHandler(cfg, managementUseCase)
	mgmtHandler := handlers.NewManagementHandler(fositeCfg, clientUseCase, samlClientUseCase, samlConnectionUseCase, authUseCase, auth2SessionUseCase, connectionUseCase, tenantUseCase, outboundGuard)
	oauthHandler := handlers.NewOAuth2Handler(Provider, km, cfg, clientUseCase, authUseCase, auth2SessionUseCase,
		connectionUseCase, tenantUseCase, scopeUseCase, jwksCache)

	oidcHandler := handlers.NewOIDCHandler(cfg, clientUseCase, authUseCase, connectionUseCase, attrMapper, webhookUseCase, federationState)
	samlHandler := handlers.NewSAMLHandler(cfg, km, samlBuilderUseCase, clientUseCase, attrMapper, authUseCase, samlConnectionUseCase,
		auth2SessionUseCase, samlClientUseCase, clientUseCase, webhookUseCase, scopeUseCase)
	webhookHandler := handlers.NewWebhookHandler(webhookUseCase, cfg)
	auditHandler := handlers.NewAuditHandler(auditUseCase)
	scopeHandler := handlers.NewScopeHandler(scopeUseCase)
	outboundPolicyHandler := handlers.NewOutboundPolicyHandler(outboundPolicyUseCase)

	public := gin.New()
	public.Use(gin.Recovery())
	public.Use(middleware.SecurityHeaders())
	public.Use(otelgin.Middleware("shyntr-public-api"))
	public.Use(middleware.StructuredLogger())

	public.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.AllowedOrigins,
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Public Routes
	public.GET("/health", healthHandler.Check)

	// Discovery & JWKS
	public.GET("/.well-known/openid-configuration", oauthHandler.Discover)
	public.GET("/.well-known/jwks.json", oauthHandler.Jwks)
	public.GET("/userinfo", oauthHandler.UserInfo)
	public.POST("/userinfo", oauthHandler.UserInfo)

	// Authentication UI Redirects (User facing)
	uiGroup := public.Group("/auth")
	uiGroup.Use(middleware.ErrorHandlerMiddleware())
	{
		uiGroup.GET("/methods", loginHandler.GetLoginMethods)
	}

	// SAML Routes
	rootSamlGroup := public.Group("/saml")
	{
		rootSamlGroup.GET("/sp/metadata", samlHandler.SPMetadata)
		rootSamlGroup.POST("/sp/acs", samlHandler.ACS)
		rootSamlGroup.GET("/sp/slo", samlHandler.SPSLO)
		rootSamlGroup.POST("/sp/slo", samlHandler.SPSLO)
		rootSamlGroup.GET("/idp/metadata", samlHandler.IDPMetadata)
		rootSamlGroup.GET("/login/:connection_id", samlHandler.Login)
		rootSamlGroup.GET("/idp/sso", samlHandler.IDPSSO)
		rootSamlGroup.POST("/idp/sso", samlHandler.IDPSSO)
		rootSamlGroup.GET("/idp/slo", samlHandler.IDPSLO)
		rootSamlGroup.POST("/idp/slo", samlHandler.IDPSLO)
		rootSamlGroup.GET("/resume", samlHandler.ResumeSAML)
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
		tenantGroup.POST("/userinfo", oauthHandler.UserInfo)

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
			samlGroup.GET("/sp/slo", samlHandler.SPSLO)
			samlGroup.POST("/sp/slo", samlHandler.SPSLO)
			samlGroup.GET("/idp/metadata", samlHandler.IDPMetadata)
			samlGroup.GET("/login/:connection_id", samlHandler.Login)
			samlGroup.GET("/idp/sso", samlHandler.IDPSSO)
			samlGroup.POST("/idp/sso", samlHandler.IDPSSO)
			samlGroup.GET("/idp/slo", samlHandler.IDPSLO)
			samlGroup.POST("/idp/slo", samlHandler.IDPSLO)
			samlGroup.GET("/resume", samlHandler.ResumeSAML)
		}

		oidcGroup := tenantGroup.Group("/oidc")
		{
			oidcGroup.GET("/login/:connection_id", oidcHandler.Login)
			oidcGroup.GET("/callback", oidcHandler.Callback)
		}
	}

	admin := gin.New()
	admin.Use(gin.Recovery())
	admin.Use(otelgin.Middleware("shyntr-admin-api"))
	admin.Use(middleware.StructuredLogger())
	admin.Use(middleware.ErrorHandlerMiddleware())
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
			// Dashboard Stats
			mgmtGroup.GET("/dashboard/stats", mgmtHandler.GetDashboardStats)

			// Tenants
			mgmtGroup.GET("/tenants", mgmtHandler.ListTenants)
			mgmtGroup.GET("/tenants/:id", mgmtHandler.GetTenant)
			mgmtGroup.POST("/tenants", mgmtHandler.CreateTenant)
			mgmtGroup.PUT("/tenants/:id", mgmtHandler.UpdateTenant)
			mgmtGroup.DELETE("/tenants/:id", mgmtHandler.DeleteTenant)
			mgmtGroup.GET("/tenants/:id/scopes", scopeHandler.List)
			mgmtGroup.GET("/tenants/:id/scopes/:scope_id", scopeHandler.Get)
			mgmtGroup.POST("/tenants/:id/scopes", scopeHandler.Create)
			mgmtGroup.PUT("/tenants/:id/scopes/:scope_id", scopeHandler.Update)
			mgmtGroup.DELETE("/tenants/:id/scopes/:scope_id", scopeHandler.Delete)

			// OAuth2 Clients
			mgmtGroup.GET("/clients", mgmtHandler.ListClients)
			mgmtGroup.GET("/clients/tenant/:tenant_id", mgmtHandler.ListClientsByTenant)
			mgmtGroup.GET("/clients/:tenant_id/:id", mgmtHandler.GetClient)
			mgmtGroup.POST("/clients", mgmtHandler.CreateClient)
			mgmtGroup.PUT("/clients/:id", mgmtHandler.UpdateClient)
			mgmtGroup.DELETE("/clients/:tenant_id/:id", mgmtHandler.DeleteClient)

			// SAML Clients (Service Providers)
			mgmtGroup.GET("/saml-clients", mgmtHandler.ListSAMLClients)
			mgmtGroup.GET("/saml-clients/tenant/:tenant_id", mgmtHandler.ListSAMLClientsByTenant)
			mgmtGroup.GET("/saml-clients/:tenant_id/:id", mgmtHandler.GetSAMLClient)
			mgmtGroup.POST("/saml-clients", mgmtHandler.CreateSAMLClient)
			mgmtGroup.PUT("/saml-clients/:id", mgmtHandler.UpdateSAMLClient)
			mgmtGroup.DELETE("/saml-clients/:tenant_id/:id", mgmtHandler.DeleteSAMLClient)

			// SAML Connections (Identity Providers)
			mgmtGroup.GET("/saml-connections", mgmtHandler.ListSAMLConnections)
			mgmtGroup.GET("/saml-connections/:tenant_id/:id", mgmtHandler.GetSAMLConnection)
			mgmtGroup.POST("/saml-connections", mgmtHandler.CreateSAMLConnection)
			mgmtGroup.PUT("/saml-connections/:id", mgmtHandler.UpdateSAMLConnection)
			mgmtGroup.DELETE("/saml-connections/:tenant_id/:id", mgmtHandler.DeleteSAMLConnection)

			// OIDC Connections
			mgmtGroup.GET("/oidc-connections", mgmtHandler.ListOIDCConnections)
			mgmtGroup.GET("/oidc-connections/:tenant_id/:id", mgmtHandler.GetOIDCConnection)
			mgmtGroup.POST("/oidc-connections", mgmtHandler.CreateOIDCConnection)
			mgmtGroup.PUT("/oidc-connections/:id", mgmtHandler.UpdateOIDCConnection)
			mgmtGroup.DELETE("/oidc-connections/:tenant_id/:id", mgmtHandler.DeleteOIDCConnection)

			//Webhook
			mgmtGroup.POST("/webhooks", webhookHandler.Create)

			//Audit
			mgmtGroup.GET("/audit/:tenant_id", auditHandler.Get)

			//Outbound Policy
			mgmtGroup.POST("/outbound-policies", outboundPolicyHandler.Create)
			mgmtGroup.GET("/outbound-policies", outboundPolicyHandler.List)
			mgmtGroup.GET("/outbound-policies/:id", outboundPolicyHandler.Get)
			mgmtGroup.PUT("/outbound-policies/:id", outboundPolicyHandler.Update)
			mgmtGroup.DELETE("/outbound-policies/:id", outboundPolicyHandler.Delete)
		}
	}

	return public, admin
}

func SetupSwaggerRouter() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.StructuredLogger())
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	return r
}
