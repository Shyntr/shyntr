package main

// @title Shyntr Identity Hub API
// @version 1.0
// @description Protocol Agnostic Zero Trust Identity Broker
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/audit"
	router "github.com/Shyntr/shyntr/internal/adapters/http"
	"github.com/Shyntr/shyntr/internal/adapters/iam"
	ldapadapter "github.com/Shyntr/shyntr/internal/adapters/ldap"
	persistence "github.com/Shyntr/shyntr/internal/adapters/persistence"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/repository"
	"github.com/Shyntr/shyntr/internal/application/security"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	utils2 "github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/application/worker"
	"github.com/Shyntr/shyntr/internal/domain/model"
	shcrypto "github.com/Shyntr/shyntr/pkg/crypto"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/Shyntr/shyntr/pkg/utils"
	"github.com/crewjam/saml"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/ory/fosite"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

func printJSON(v interface{}) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Fatalf("JSON marshaling failed: %v", err)
	}
	fmt.Println(string(b))
}

func parseRequiredDuration(name, value string) time.Duration {
	d, err := time.ParseDuration(value)
	if err != nil {
		log.Fatalf("Invalid %s duration %q: %v", name, value, err)
	}
	return d
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "shyntr",
		Short: "Shyntr - Protocol Agnostic Identity Hub",
	}

	var migrateCmd = &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			logger.InitLogger(cfg.LogLevel)
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			if err := persistence.MigrateDB(db); err != nil {
				log.Fatalf("Migration failed: %v", err)
			}

			logger.Log.Info("Running OAuth 2.1 security enforcements on existing data...")
			if err := db.Exec("UPDATE o_auth2_clients SET enforce_pkce = true WHERE enforce_pkce = false").Error; err != nil {
				logger.Log.Error("Failed to enforce PKCE on existing clients", zap.Error(err))
			} else {
				logger.Log.Info("PKCE enforced for all existing clients.")
			}

			logger.Log.Info("Database migration completed successfully.")
			scopeRepo := repository.NewScopeRepository(db)
			if err := utils2.SeedSystemScopesForTenant(context.Background(), scopeRepo, cfg.DefaultTenantID); err != nil {
				logger.Log.Error("Failed to seed system scopes during migration", zap.Error(err))
			} else {
				logger.Log.Info("System scopes verified/seeded successfully.")
			}
		},
	}

	// ==========================================
	// TENANT COMMANDS
	// ==========================================

	var (
		tenantID, tenantName, tenantDisplay, tenantDesc string
	)
	var createTenantCmd = &cobra.Command{
		Use:   "create-tenant",
		Short: "Create a new tenant",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			auditLogger := audit.NewAuditLogger(db)
			if tenantID == "" {
				tenantID = uuid.New().String()
			}
			if tenantName == "" {
				tenantName = tenantID
			}
			if tenantDisplay == "" {
				tenantDisplay = tenantName
			}

			tenant := models.TenantGORM{
				ID:          tenantID,
				Name:        tenantName,
				DisplayName: tenantDisplay,
				Description: tenantDesc,
			}
			if err := db.Create(&tenant).Error; err != nil {
				log.Fatalf("Failed: %v", err)
			}
			auditLogger.Log(tenant.ID, "system_cli", "cli.tenant.create", "127.0.0.1", "shyntr-cli", map[string]interface{}{
				"tenant_name": tenant.Name,
			})
			log.Printf("Tenant created: %s (%s)", tenant.Name, tenant.ID)
		},
	}
	createTenantCmd.Flags().StringVar(&tenantID, "id", "", "Tenant ID (slug)")
	createTenantCmd.Flags().StringVar(&tenantName, "name", "", "Tenant Name")
	createTenantCmd.Flags().StringVar(&tenantDisplay, "display-name", "", "Display Name")
	createTenantCmd.Flags().StringVar(&tenantDesc, "desc", "CLI Created", "Description")

	var getTenantCmd = &cobra.Command{
		Use:   "get-tenant [id]",
		Short: "Get tenant details",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			var tenant models.TenantGORM
			if err := db.First(&tenant, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Tenant not found: %v", err)
			}
			printJSON(tenant)
		},
	}

	var updateTenantCmd = &cobra.Command{
		Use:   "update-tenant [id]",
		Short: "Update tenant details",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			auditLogger := audit.NewAuditLogger(db)
			updates := make(map[string]interface{})
			if tenantName != "" {
				updates["name"] = tenantName
			}
			if tenantDisplay != "" {
				updates["display_name"] = tenantDisplay
			}

			if len(updates) == 0 {
				log.Println("No changes detected.")
				return
			}

			if err := db.Model(&models.TenantGORM{}).Where("id = ?", args[0]).Updates(updates).Error; err != nil {
				log.Fatalf("Update failed: %v", err)
			}
			auditLogger.Log(args[0], "system_cli", "cli.tenant.update", "127.0.0.1", "shyntr-cli", updates)
			log.Println("Tenant updated.")
		},
	}
	updateTenantCmd.Flags().StringVar(&tenantName, "name", "", "New Tenant Name")
	updateTenantCmd.Flags().StringVar(&tenantDisplay, "display-name", "", "New Display Name")

	var deleteTenantCmd = &cobra.Command{
		Use:   "delete-tenant [id]",
		Short: "Delete a tenant (Cannot delete 'default')",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if args[0] == "default" {
				log.Fatal("Cannot delete default tenant via CLI")
			}
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			auditLogger := audit.NewAuditLogger(db)
			if err := db.Delete(&models.TenantGORM{}, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("DeleteByClient failed: %v", err)
			}
			auditLogger.Log(args[0], "system_cli", "cli.tenant.delete", "127.0.0.1", "shyntr-cli", map[string]interface{}{
				"tenant_id": args[0],
			})
			log.Println("Tenant deleted.")
		},
	}

	// ==========================================
	// SCOPE COMMANDS
	// ==========================================

	var (
		scopeName, scopeDesc string
		scopeClaims          []string
		scopeIsSystem        bool
	)

	var createScopeCmd = &cobra.Command{
		Use:   "create-scope",
		Short: "Create a new scope for a tenant",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			auditLogger := audit.NewAuditLogger(db)

			if tenantID == "" {
				tenantID = "default"
			}
			if scopeName == "" {
				log.Fatal("Scope name is required")
			}

			scopeID := uuid.New().String()
			scope := models.ScopeGORM{
				ID:          scopeID,
				TenantID:    tenantID,
				Name:        strings.ToLower(strings.TrimSpace(scopeName)),
				Description: scopeDesc,
				Claims:      pq.StringArray(scopeClaims),
				IsSystem:    scopeIsSystem,
				Active:      true,
			}

			if err := db.Create(&scope).Error; err != nil {
				log.Fatalf("Failed to create scope: %v", err)
			}
			auditLogger.Log(tenantID, "system_cli", "cli.scope.create", "127.0.0.1", "shyntr-cli", map[string]interface{}{"scope_name": scope.Name})
			log.Printf("Scope created successfully: %s (%s)", scope.Name, scope.ID)
		},
	}
	createScopeCmd.Flags().StringVar(&tenantID, "tenant-id", "default", "Tenant ID")
	createScopeCmd.Flags().StringVar(&scopeName, "name", "", "Scope Name (Required)")
	createScopeCmd.Flags().StringVar(&scopeDesc, "desc", "", "Scope Description")
	createScopeCmd.Flags().StringSliceVar(&scopeClaims, "claims", nil, "Comma separated claims (e.g. email,email_verified)")
	createScopeCmd.Flags().BoolVar(&scopeIsSystem, "system", false, "Is System Scope?")

	createScopeCmd.MarkFlagRequired("name")

	var getScopeCmd = &cobra.Command{
		Use:   "get-scope [id]",
		Short: "Get scope details",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			var scope models.ScopeGORM
			if err := db.First(&scope, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Scope not found: %v", err)
			}
			printJSON(scope)
		},
	}

	var updateScopeCmd = &cobra.Command{
		Use:   "update-scope [id]",
		Short: "Update scope details",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			updates := make(map[string]interface{})
			if scopeName != "" {
				updates["name"] = strings.ToLower(strings.TrimSpace(scopeName))
			}
			if scopeDesc != "" {
				updates["description"] = scopeDesc
			}
			if len(scopeClaims) > 0 {
				updates["claims"] = pq.StringArray(scopeClaims)
			}

			if len(updates) == 0 {
				log.Println("No changes detected.")
				return
			}
			if err := db.Model(&models.ScopeGORM{}).Where("id = ?", args[0]).Updates(updates).Error; err != nil {
				log.Fatalf("Update failed: %v", err)
			}
			log.Println("Scope updated.")
		},
	}
	updateScopeCmd.Flags().StringVar(&scopeName, "name", "", "New Scope Name")
	updateScopeCmd.Flags().StringVar(&scopeDesc, "desc", "", "New Description")
	updateScopeCmd.Flags().StringSliceVar(&scopeClaims, "claims", nil, "New Claims")

	var deleteScopeCmd = &cobra.Command{
		Use:   "delete-scope [id]",
		Short: "DeleteByClient a scope",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			var scope models.ScopeGORM
			if err := db.First(&scope, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Scope not found")
			}
			if scope.IsSystem {
				log.Fatalf("Cannot delete a system scope via CLI")
			}

			if err := db.Delete(&models.ScopeGORM{}, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("DeleteByClient Failed: %v", err)
			}
			log.Println("Scope deleted.")
		},
	}
	// ==========================================
	// OIDC CLIENT COMMANDS
	// ==========================================

	var (
		clientID, clientName, clientSecret, authMethod                         string
		redirectURIs, postLogoutURIs, clientScopes, clientAudience, grantTypes []string
		isPublic, skipConsent                                                  bool
	)
	var createClientCmd = &cobra.Command{
		Use:   "create-client",
		Short: "Create OIDC Client",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}

			if tenantID == "" {
				tenantID = "default"
			}
			if clientID == "" {
				clientID = uuid.New().String()
			}
			if clientName == "" {
				clientName = "New Client " + clientID
			}
			if clientSecret == "" && !isPublic {
				clientSecret, err = utils.GenerateRandomHex(32)
				if err != nil {
					log.Fatalf("Failed to generate client secret: %v", err)
				}
			}
			if len(redirectURIs) == 0 {
				redirectURIs = []string{"http://localhost:8080/callback"}
			}
			if len(clientScopes) == 0 {
				clientScopes = []string{"openid", "profile", "email", "offline_access"}
			}

			hashedSecret := ""
			if clientSecret != "" {
				fositeCfg := &fosite.Config{GlobalSecret: []byte(cfg.AppSecret)}
				hashedSecret, err = shcrypto.HashSecret(context.Background(), fositeCfg, clientSecret)
				if err != nil {
					log.Fatalf("Failed to hash client secret: %v", err)
				}
			}

			if authMethod == "" {
				authMethod = "client_secret_basic"
			}
			if isPublic {
				authMethod = "none"
			}

			if len(grantTypes) == 0 {
				grantTypes = []string{"authorization_code"}
				if !isPublic {
					grantTypes = append(grantTypes, "client_credentials")
				}
			}

			client := models.OAuth2ClientGORM{
				ID:                      clientID,
				TenantID:                tenantID,
				Name:                    clientName,
				Secret:                  hashedSecret,
				RedirectURIs:            redirectURIs,
				PostLogoutRedirectURIs:  postLogoutURIs,
				Audience:                clientAudience,
				GrantTypes:              grantTypes,
				ResponseTypes:           []string{"code"},
				ResponseModes:           []string{"query", "form_post"},
				Scopes:                  clientScopes,
				TokenEndpointAuthMethod: authMethod,
				Public:                  isPublic,
				EnforcePKCE:             true, // OAuth 2.1 Requirement
				SkipConsent:             skipConsent,
			}

			if err := db.Create(&client).Error; err != nil {
				log.Fatalf("Failed: %v", err)
			}

			log.Printf("Client Created Successfully!")
			log.Printf("Tenant: %s", client.TenantID)
			log.Printf("Client ID: %s", client.ID)
			if !isPublic {
				log.Printf("Client Secret: %s", clientSecret)
			}
		},
	}
	createClientCmd.Flags().StringVar(&tenantID, "tenant-id", "default", "Tenant ID")
	createClientCmd.Flags().StringVar(&clientID, "client-id", "", "Client ID (Auto-generated if empty)")
	createClientCmd.Flags().StringVar(&clientName, "name", "", "Client Name")
	createClientCmd.Flags().StringVar(&clientSecret, "secret", "", "Client Secret (Auto-generated if empty)")
	createClientCmd.Flags().StringVar(&authMethod, "auth-method", "", "Token endpoint authentication method")
	createClientCmd.Flags().StringSliceVar(&redirectURIs, "redirect-uris", nil, "Comma separated Redirect URIs")
	createClientCmd.Flags().StringSliceVar(&postLogoutURIs, "post-logout-uris", nil, "Comma separated Post Logout URIs")
	createClientCmd.Flags().StringSliceVar(&clientScopes, "scopes", nil, "Comma separated scopes")
	createClientCmd.Flags().StringSliceVar(&clientAudience, "audience", nil, "Comma separated audiences")
	createClientCmd.Flags().BoolVar(&isPublic, "public", false, "Is Public Client (SPA/Mobile)")
	createClientCmd.Flags().BoolVar(&skipConsent, "skip-consent", false, "Skip user consent screen")

	var injectJWKSCmd = &cobra.Command{
		Use:   "inject-jwks [client_id] [jwks_file]",
		Short: "Directly injects a JWKS payload into the client's database record",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			jwksBytes, err := os.ReadFile(args[1])
			if err != nil {
				log.Fatalf("Failed to read JWKS file: %v", err)
			}

			result := db.Exec(`UPDATE o_auth2_clients SET json_web_keys = ? WHERE id = ?`, string(jwksBytes), args[0])
			if result.Error != nil {
				log.Fatalf("Failed to inject JWKS: %v", result.Error)
			}
			if result.RowsAffected == 0 {
				log.Fatalf("Client %s not found", args[0])
			}
			log.Printf("Successfully injected JWKS into client %s. Fosite will now recognize the Public Key.", args[0])
		},
	}
	var getClientCmd = &cobra.Command{
		Use:   "get-client [client_id]",
		Short: "Get OIDC Client details",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			var client models.OAuth2ClientGORM
			if err := db.First(&client, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Client not found: %v", err)
			}
			printJSON(client)
		},
	}

	var updateClientCmd = &cobra.Command{
		Use:   "update-client [client_id]",
		Short: "Update OIDC Client details",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			auditLogger := audit.NewAuditLogger(db)
			updates := make(map[string]interface{})
			if clientName != "" {
				updates["name"] = clientName
			}
			if len(redirectURIs) > 0 {
				updates["redirect_uris"] = pq.StringArray(redirectURIs)
			}
			if len(postLogoutURIs) > 0 {
				updates["post_logout_redirect_uris"] = pq.StringArray(postLogoutURIs)
			}
			if len(clientScopes) > 0 {
				updates["scopes"] = pq.StringArray(clientScopes)
			}
			if clientSecret != "" {
				fositeCfg := &fosite.Config{GlobalSecret: []byte(cfg.AppSecret)}
				hashed, hashErr := shcrypto.HashSecret(context.Background(), fositeCfg, clientSecret)
				if hashErr != nil {
					log.Fatalf("Failed to hash client secret: %v", hashErr)
				}
				updates["secret"] = hashed
			}
			if len(updates) == 0 {
				log.Println("No changes detected.")
				return
			}

			var client models.OAuth2ClientGORM
			if err := db.Select("tenant_id").First(&client, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Client not found: %v", err)
			}
			if err := db.Model(&models.OAuth2ClientGORM{}).Where("id = ?", args[0]).Updates(updates).Error; err != nil {
				log.Fatalf("Update failed: %v", err)
			}
			auditLogger.Log(client.TenantID, "system_cli", "cli.client.oidc.update", "127.0.0.1", "shyntr-cli", map[string]interface{}{"client_id": args[0]})
			log.Println("Client updated.")
		},
	}
	updateClientCmd.Flags().StringVar(&clientName, "name", "", "New Client Name")
	updateClientCmd.Flags().StringSliceVar(&redirectURIs, "redirect-uris", nil, "New Redirect URIs")
	updateClientCmd.Flags().StringSliceVar(&postLogoutURIs, "post-logout-uris", nil, "New Post Logout URIs")
	updateClientCmd.Flags().StringSliceVar(&clientScopes, "scopes", nil, "New Scopes")
	updateClientCmd.Flags().StringVar(&clientSecret, "secret", "", "New Client Secret")

	var deleteClientCmd = &cobra.Command{
		Use:   "delete-client [client_id]",
		Short: "DeleteByClient OIDC Client",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			auditLogger := audit.NewAuditLogger(db)
			var client models.OAuth2ClientGORM
			if err := db.Select("tenant_id").First(&client, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Client not found: %v", err)
			}
			if err := db.Delete(&models.OAuth2ClientGORM{}, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("DeleteByClient failed: %v", err)
			}
			auditLogger.Log(client.TenantID, "system_cli", "cli.client.oidc.delete", "127.0.0.1", "shyntr-cli", map[string]interface{}{"client_id": args[0]})
			log.Println("Client deleted.")
		},
	}

	// ==========================================
	// SAML CLIENT COMMANDS (SP)
	// ==========================================

	var (
		samlEntityID, samlACSURL, samlSLOURL        string
		samlAllowedScopes                           []string
		samlForceAuthn, signResponse, signAssertion bool
	)
	var createSAMLClientCmd = &cobra.Command{
		Use:   "create-saml-client",
		Short: "Create SAML Service Provider",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}

			if tenantID == "" {
				tenantID = "default"
			}
			if samlEntityID == "" || samlACSURL == "" {
				log.Fatal("Entity ID and ACS URL are required flags.")
			}
			if clientName == "" {
				clientName = "SAML App"
			}

			client := models.SAMLClientGORM{
				TenantID:      tenantID,
				Name:          clientName,
				EntityID:      samlEntityID,
				ACSURL:        samlACSURL,
				SLOURL:        samlSLOURL,
				AllowedScopes: pq.StringArray(samlAllowedScopes),
				ForceAuthn:    samlForceAuthn,
				Active:        true,
				SignResponse:  signResponse,
				SignAssertion: signAssertion,
			}

			if err := db.Create(&client).Error; err != nil {
				log.Fatalf("Failed: %v", err)
			}
			log.Printf("SAML Client created: %s", client.EntityID)
		},
	}
	createSAMLClientCmd.Flags().StringVar(&tenantID, "tenant-id", "default", "Tenant ID")
	createSAMLClientCmd.Flags().StringVar(&clientName, "name", "", "App Name")
	createSAMLClientCmd.Flags().StringVar(&samlEntityID, "entity-id", "", "Entity ID (Required)")
	createSAMLClientCmd.Flags().StringVar(&samlACSURL, "acs-url", "", "ACS URL (Required)")
	createSAMLClientCmd.Flags().StringVar(&samlSLOURL, "slo-url", "", "SLO URL")
	createSAMLClientCmd.Flags().StringSliceVar(&samlAllowedScopes, "allowed-scopes", nil, "Comma separated allowed scopes")
	createSAMLClientCmd.Flags().BoolVar(&samlForceAuthn, "force-authn", false, "Force Authentication (ForceAuthn)")
	createSAMLClientCmd.Flags().BoolVar(&signResponse, "sign-response", false, "Sign response")
	createSAMLClientCmd.Flags().BoolVar(&signAssertion, "sign-assertion", false, "Sign Assertions")

	_ = createSAMLClientCmd.MarkFlagRequired("entity-id")
	_ = createSAMLClientCmd.MarkFlagRequired("acs-url")

	var getSAMLClientCmd = &cobra.Command{
		Use:   "get-saml-client [entity_id]",
		Short: "Get SAML Client",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("DB Error: %v", err)
			}
			var client models.SAMLClientGORM
			if err := db.First(&client, "entity_id = ?", args[0]).Error; err != nil {
				log.Fatalf("Not Found: %v", err)
			}
			printJSON(client)
		},
	}

	var updateSAMLClientCmd = &cobra.Command{
		Use:   "update-saml-client [entity_id]",
		Short: "Update SAML Client (SP) details",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			auditLogger := audit.NewAuditLogger(db)
			updates := make(map[string]interface{})
			if samlACSURL != "" {
				updates["acs_url"] = samlACSURL
			}
			if samlSLOURL != "" {
				updates["slo_url"] = samlSLOURL
			}
			if clientName != "" {
				updates["name"] = clientName
			}
			if len(samlAllowedScopes) > 0 {
				updates["allowed_scopes"] = pq.StringArray(samlAllowedScopes)
			}

			if len(updates) == 0 {
				log.Println("No changes detected.")
				return
			}
			var client models.SAMLClientGORM
			if err := db.Select("tenant_id").First(&client, "entity_id = ?", args[0]).Error; err != nil {
				log.Fatalf("SAML client not found: %v", err)
			}
			if err := db.Model(&models.SAMLClientGORM{}).Where("entity_id = ?", args[0]).Updates(updates).Error; err != nil {
				log.Fatalf("Update failed: %v", err)
			}
			auditLogger.Log(client.TenantID, "system_cli", "cli.client.saml.update", "127.0.0.1", "shyntr-cli", map[string]interface{}{"entity_id": args[0]})
			log.Println("SAML Client updated.")
		},
	}
	updateSAMLClientCmd.Flags().StringVar(&samlACSURL, "acs-url", "", "New ACS URL")
	updateSAMLClientCmd.Flags().StringVar(&samlSLOURL, "slo-url", "", "New SLO URL")
	updateSAMLClientCmd.Flags().StringVar(&clientName, "name", "", "New App Name")
	updateSAMLClientCmd.Flags().StringSliceVar(&samlAllowedScopes, "allowed-scopes", nil, "New Allowed Scopes")

	var deleteSAMLClientCmd = &cobra.Command{
		Use:   "delete-saml-client [entity_id]",
		Short: "DeleteByClient SAML Client",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("DB Error: %v", err)
			}
			auditLogger := audit.NewAuditLogger(db)
			var client models.SAMLClientGORM
			if err := db.Select("tenant_id").First(&client, "entity_id = ?", args[0]).Error; err != nil {
				log.Fatalf("SAML client not found: %v", err)
			}
			if err := db.Where("entity_id = ?", args[0]).Delete(&models.SAMLClientGORM{}).Error; err != nil {
				log.Fatalf("DeleteByClient Failed: %v", err)
			}
			auditLogger.Log(client.TenantID, "system_cli", "cli.client.saml.delete", "127.0.0.1", "shyntr-cli", map[string]interface{}{"entity_id": args[0]})
			log.Println("SAML Client deleted.")
		},
	}

	// ==========================================
	// SAML CONNECTION COMMANDS (IDP)
	// ==========================================

	var metadataFile, metadataURL string
	var signRequest bool
	var createSAMLConnectionCmd = &cobra.Command{
		Use:   "create-saml-connection",
		Short: "Register SAML IDP Connection",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("DB Error: %v", err)
			}

			if tenantID == "" {
				tenantID = "default"
			}
			if metadataFile == "" && metadataURL == "" {
				log.Fatal("Either --metadata-file or --metadata-url is required")
			}
			if clientName == "" {
				clientName = "SAML IDP"
			}

			var xmlBytes []byte
			var entityID string

			if metadataFile != "" {
				xmlBytes, err = os.ReadFile(metadataFile)
				if err != nil {
					log.Fatalf("Failed to read metadata file: %v", err)
				}

				meta := &saml.EntityDescriptor{}
				if err := xml.Unmarshal(xmlBytes, meta); err != nil {
					log.Fatalf("Failed to parse metadata XML: %v", err)
				}
				entityID = meta.EntityID
				if entityID == "" {
					log.Fatal("Parsed metadata XML does not contain an EntityID")
				}
			} else if metadataURL != "" {
				outboundPolicyRepo := repository.NewOutboundPolicyRepository(db)
				outboundGuard := security.NewOutboundGuard(outboundPolicyRepo, cfg.SkipTLSVerify)
				descriptor, rawXML, fetchErr := utils2.FetchAndParseMetadata(context.Background(), tenantID, metadataURL, outboundGuard)
				if fetchErr != nil {
					log.Fatalf("Failed to fetch metadata URL: %v", fetchErr)
				}
				if descriptor == nil || descriptor.EntityID == "" {
					log.Fatal("Fetched metadata does not contain a valid EntityID")
				}
				xmlBytes = []byte(rawXML)
				entityID = descriptor.EntityID
			}
			conn := models.SAMLConnectionGORM{
				TenantID:       tenantID,
				Name:           clientName,
				IdpMetadataXML: string(xmlBytes),
				IdpEntityID:    entityID,
				MetadataURL:    metadataURL,
				SignRequest:    signRequest,
				Active:         true,
			}

			if err := db.Create(&conn).Error; err != nil {
				log.Fatalf("Failed: %v", err)
			}
			log.Printf("SAML Connection created: %s", conn.Name)
		},
	}
	createSAMLConnectionCmd.Flags().StringVar(&tenantID, "tenant-id", "default", "Tenant ID")
	createSAMLConnectionCmd.Flags().StringVar(&clientName, "name", "", "Connection Name")
	createSAMLConnectionCmd.Flags().StringVar(&metadataFile, "metadata-file", "", "Path to metadata XML file")
	createSAMLConnectionCmd.Flags().StringVar(&metadataURL, "metadata-url", "", "URL to fetch metadata XML")
	createSAMLConnectionCmd.Flags().BoolVar(&signRequest, "sign-request", false, "Sign AuthnRequests")

	var getSAMLConnectionCmd = &cobra.Command{
		Use:   "get-saml-connection [id]",
		Short: "Get SAML Connection",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("DB Error: %v", err)
			}
			var conn models.SAMLConnectionGORM
			if err := db.First(&conn, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Not Found: %v", err)
			}
			printJSON(conn)
		},
	}

	var deleteSAMLConnectionCmd = &cobra.Command{
		Use:   "delete-saml-connection [id]",
		Short: "DeleteByClient SAML Connection",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("DB Error: %v", err)
			}
			auditLogger := audit.NewAuditLogger(db)
			var conn models.SAMLConnectionGORM
			if err := db.Select("tenant_id").First(&conn, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("SAML connection not found: %v", err)
			}
			if err := db.Delete(&models.SAMLConnectionGORM{}, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("DeleteByClient Failed: %v", err)
			}
			auditLogger.Log(conn.TenantID, "system_cli", "cli.connection.saml.delete", "127.0.0.1", "shyntr-cli", map[string]interface{}{"connection_id": args[0]})
			log.Println("SAML Connection deleted.")
		},
	}

	// ==========================================
	// OIDC CONNECTION COMMANDS (External IDP)
	// ==========================================

	var issuerURL string
	var oidcScopes []string
	var createOIDCConnectionCmd = &cobra.Command{
		Use:   "create-oidc-connection",
		Short: "Register OIDC Provider",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("DB Error: %v", err)
			}

			if tenantID == "" {
				tenantID = "default"
			}
			if issuerURL == "" || clientID == "" || clientSecret == "" {
				log.Fatal("Issuer, Client ID, and Client Secret are required.")
			}
			if clientName == "" {
				clientName = "OIDC Provider"
			}
			if len(oidcScopes) == 0 {
				oidcScopes = []string{"openid", "profile", "email"}
			}

			outboundPolicyRepo := repository.NewOutboundPolicyRepository(db)
			outboundGuard := security.NewOutboundGuard(outboundPolicyRepo, cfg.SkipTLSVerify)

			if _, _, err := outboundGuard.ValidateURL(
				context.Background(),
				tenantID,
				model.OutboundTargetOIDCDiscovery,
				issuerURL,
			); err != nil {
				log.Fatalf("issuer url violates outbound policy: %v", err)
			}

			conn := models.OIDCConnectionGORM{
				TenantID:     tenantID,
				Name:         clientName,
				IssuerURL:    issuerURL,
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Active:       true,
				Scopes:       pq.StringArray(oidcScopes),
			}

			if err := db.Create(&conn).Error; err != nil {
				log.Fatalf("Failed: %v", err)
			}
			log.Printf("OIDC Connection created: %s", conn.Name)
		},
	}
	createOIDCConnectionCmd.Flags().StringVar(&tenantID, "tenant-id", "default", "Tenant ID")
	createOIDCConnectionCmd.Flags().StringVar(&clientName, "name", "", "Connection Name")
	createOIDCConnectionCmd.Flags().StringVar(&issuerURL, "issuer", "", "Issuer URL")
	createOIDCConnectionCmd.Flags().StringVar(&clientID, "client-id", "", "Client ID")
	createOIDCConnectionCmd.Flags().StringVar(&clientSecret, "client-secret", "", "Client Secret")
	createOIDCConnectionCmd.Flags().StringSliceVar(&oidcScopes, "scopes", nil, "Comma separated scopes")

	_ = createOIDCConnectionCmd.MarkFlagRequired("issuer")
	_ = createOIDCConnectionCmd.MarkFlagRequired("client-id")
	_ = createOIDCConnectionCmd.MarkFlagRequired("client-secret")

	var getOIDCConnectionCmd = &cobra.Command{
		Use:   "get-oidc-connection [id]",
		Short: "Get OIDC Connection",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("DB Error: %v", err)
			}
			var conn models.OIDCConnectionGORM
			if err := db.First(&conn, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Not Found: %v", err)
			}
			printJSON(conn)
		},
	}

	var deleteOIDCConnectionCmd = &cobra.Command{
		Use:   "delete-oidc-connection [id]",
		Short: "DeleteByClient OIDC Connection",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("DB Error: %v", err)
			}
			auditLogger := audit.NewAuditLogger(db)
			var conn models.OIDCConnectionGORM
			if err := db.Select("tenant_id").First(&conn, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("OIDC connection not found: %v", err)
			}
			if err := db.Delete(&models.OIDCConnectionGORM{}, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("DeleteByClient Failed: %v", err)
			}
			auditLogger.Log(conn.TenantID, "system_cli", "cli.connection.oidc.delete", "127.0.0.1", "shyntr-cli", map[string]interface{}{"connection_id": args[0]})
			log.Println("OIDC Connection deleted.")
		},
	}

	// ==========================================
	// LDAP CONNECTION COMMANDS
	// ==========================================

	var (
		ldapServerURL, ldapBindDN, ldapBindPassword, ldapBaseDN string
		ldapStartTLS, ldapInsecureSkipVerify                    bool
	)

	var createLDAPConnectionCmd = &cobra.Command{
		Use:   "create-ldap-connection",
		Short: "Register LDAP Directory Connection",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("DB Error: %v", err)
			}
			if tenantID == "" {
				tenantID = "default"
			}
			if ldapServerURL == "" || ldapBaseDN == "" {
				log.Fatal("--server-url and --base-dn are required")
			}
			if clientName == "" {
				clientName = "LDAP Directory"
			}
			ldapRepo := repository.NewLDAPConnectionRepository(db, []byte(cfg.AppSecret))
			ldapUseCase := usecase.NewLDAPConnectionUseCase(ldapRepo, ldapadapter.NewLDAPDialer(), audit.NewAuditLogger(db), nil, nil)
			conn, connErr := ldapUseCase.CreateConnection(context.Background(), &model.LDAPConnection{
				TenantID:              tenantID,
				Name:                  clientName,
				ServerURL:             ldapServerURL,
				BindDN:                ldapBindDN,
				BindPassword:          ldapBindPassword,
				BaseDN:                ldapBaseDN,
				StartTLS:              ldapStartTLS,
				TLSInsecureSkipVerify: ldapInsecureSkipVerify,
			}, "127.0.0.1", "shyntr-cli")
			if connErr != nil {
				log.Fatalf("Failed: %v", connErr)
			}
			log.Printf("LDAP Connection created: %s (%s)", conn.Name, conn.ID)
		},
	}
	createLDAPConnectionCmd.Flags().StringVar(&tenantID, "tenant-id", "default", "Tenant ID")
	createLDAPConnectionCmd.Flags().StringVar(&clientName, "name", "", "Connection Name")
	createLDAPConnectionCmd.Flags().StringVar(&ldapServerURL, "server-url", "", "LDAP Server URL (Required)")
	createLDAPConnectionCmd.Flags().StringVar(&ldapBindDN, "bind-dn", "", "Bind DN")
	createLDAPConnectionCmd.Flags().StringVar(&ldapBindPassword, "bind-password", "", "Bind Password")
	createLDAPConnectionCmd.Flags().StringVar(&ldapBaseDN, "base-dn", "", "Base DN (Required)")
	createLDAPConnectionCmd.Flags().BoolVar(&ldapStartTLS, "start-tls", false, "Use StartTLS")
	createLDAPConnectionCmd.Flags().BoolVar(&ldapInsecureSkipVerify, "insecure-skip-verify", false, "Skip TLS verification")
	_ = createLDAPConnectionCmd.MarkFlagRequired("server-url")
	_ = createLDAPConnectionCmd.MarkFlagRequired("base-dn")

	var getLDAPConnectionCmd = &cobra.Command{
		Use:   "get-ldap-connection [id]",
		Short: "Get LDAP Connection",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("DB Error: %v", err)
			}
			ldapRepo := repository.NewLDAPConnectionRepository(db, []byte(cfg.AppSecret))
			ldapUseCase := usecase.NewLDAPConnectionUseCase(ldapRepo, ldapadapter.NewLDAPDialer(), audit.NewAuditLogger(db), nil, nil)
			conn, connErr := ldapUseCase.GetConnection(context.Background(), "", args[0])
			if connErr != nil {
				log.Fatalf("Not found: %v", connErr)
			}
			printJSON(conn)
		},
	}

	var deleteLDAPConnectionCmd = &cobra.Command{
		Use:   "delete-ldap-connection [id]",
		Short: "Delete LDAP Connection",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if tenantID == "" {
				log.Fatal("--tenant-id is required")
			}
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("DB Error: %v", err)
			}
			auditLogger := audit.NewAuditLogger(db)
			ldapRepo := repository.NewLDAPConnectionRepository(db, []byte(cfg.AppSecret))
			ldapUseCase := usecase.NewLDAPConnectionUseCase(ldapRepo, ldapadapter.NewLDAPDialer(), auditLogger, nil, nil)
			if delErr := ldapUseCase.DeleteConnection(context.Background(), tenantID, args[0], "127.0.0.1", "shyntr-cli"); delErr != nil {
				log.Fatalf("Delete failed: %v", delErr)
			}
			log.Println("LDAP Connection deleted.")
		},
	}
	deleteLDAPConnectionCmd.Flags().StringVar(&tenantID, "tenant-id", "", "Tenant ID (Required)")
	_ = deleteLDAPConnectionCmd.MarkFlagRequired("tenant-id")

	var importKeyCmd = &cobra.Command{
		Use:   "import-key",
		Short: "Inject a CA-signed keypair into the Identity Hub",
		Long:  "Used in High-Assurance (PKI) environments to manually rotate keys bypassing AutoRollover.",
		Run: func(cmd *cobra.Command, args []string) {
			use, _ := cmd.Flags().GetString("use")
			certPath, _ := cmd.Flags().GetString("cert")
			keyPath, _ := cmd.Flags().GetString("key")

			if use != "sig" && use != "enc" {
				log.Fatal("Invalid use type. Must be 'sig' or 'enc'.")
			}

			cfg := config.LoadConfig()
			logger.InitLogger(cfg.LogLevel)
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("DB Connection failed: %v", err)
			}

			keyRepo := repository.NewCryptoKeyRepository(db)
			keyMgr := utils2.NewKeyManager(keyRepo, cfg)

			certBytes, err := os.ReadFile(certPath)
			if err != nil {
				log.Fatalf("Failed to read certificate file: %v", err)
			}

			keyBytes, err := os.ReadFile(keyPath)
			if err != nil {
				log.Fatalf("Failed to read private key file: %v", err)
			}

			block, _ := pem.Decode(keyBytes)
			if block == nil {
				log.Fatal("Failed to decode PEM block from private key file")
			}

			privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				parsedKey, err8 := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err8 != nil {
					log.Fatalf("Failed to parse private key: %v", err8)
				}
				var ok bool
				privKey, ok = parsedKey.(*rsa.PrivateKey)
				if !ok {
					log.Fatal("Provided key is not a valid RSA Private Key")
				}
			}

			ctx := context.Background()
			if _, err := keyMgr.ImportKey(ctx, use, privKey, certBytes); err != nil {
				log.Fatalf("CRITICAL: Failed to import key: %v", err)
			}

			log.Printf("SUCCESS: CA-signed key successfully injected for use '%s'.", use)
		},
	}

	importKeyCmd.Flags().String("use", "sig", "Key usage type ('sig' or 'enc')")
	importKeyCmd.Flags().String("cert", "", "Path to the CA-signed X.509 certificate (PEM)")
	importKeyCmd.Flags().String("key", "", "Path to the unencrypted RSA private key (PEM)")
	if err := importKeyCmd.MarkFlagRequired("cert"); err != nil {
		log.Fatal(err)
	}
	if err := importKeyCmd.MarkFlagRequired("key"); err != nil {
		log.Fatal(err)
	}

	// ==========================================
	// SERVER START
	// ==========================================

	var serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start the Identity Broker server",
		Run: func(cmd *cobra.Command, args []string) {
			runServer()
		},
	}

	rootCmd.AddCommand(
		migrateCmd,
		createTenantCmd, getTenantCmd, updateTenantCmd, deleteTenantCmd,
		createScopeCmd, getScopeCmd, updateScopeCmd, deleteScopeCmd,
		createClientCmd, getClientCmd, updateClientCmd, deleteClientCmd, injectJWKSCmd,
		createSAMLClientCmd, getSAMLClientCmd, updateSAMLClientCmd, deleteSAMLClientCmd,
		createSAMLConnectionCmd, getSAMLConnectionCmd, deleteSAMLConnectionCmd,
		createOIDCConnectionCmd, getOIDCConnectionCmd, deleteOIDCConnectionCmd,
		createLDAPConnectionCmd, getLDAPConnectionCmd, deleteLDAPConnectionCmd,
		serveCmd, importKeyCmd,
	)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runServer() {
	cfg := config.LoadConfig()
	logger.InitLogger(cfg.LogLevel)

	accessTokenLifespan := parseRequiredDuration("ACCESS_TOKEN_LIFESPAN", cfg.AccessTokenLifespan)
	refreshTokenLifespan := parseRequiredDuration("REFRESH_TOKEN_LIFESPAN", cfg.RefreshTokenLifespan)
	idTokenLifespan := parseRequiredDuration("ID_TOKEN_LIFESPAN", cfg.IDTokenLifespan)

	db, err := persistence.ConnectDB(cfg)
	if err != nil {
		logger.Log.Fatal("Database connection failed", zap.Error(err))
	}

	var count int64
	if err := db.Model(&model.Tenant{}).Where("id = ?", cfg.DefaultTenantID).Count(&count).Error; err == nil && count == 0 {
		logger.Log.Info("Default tenant not found, creating...", zap.String("id", cfg.DefaultTenantID))
		persistence.SeedDefaultTenant(db, cfg)
	}

	fositeConfig := &fosite.Config{
		AccessTokenLifespan:        accessTokenLifespan,
		AuthorizeCodeLifespan:      10 * time.Minute,
		IDTokenLifespan:            idTokenLifespan,
		RefreshTokenLifespan:       refreshTokenLifespan,
		GlobalSecret:               []byte(cfg.AppSecret),
		IDTokenIssuer:              cfg.BaseIssuerURL,
		SendDebugMessagesToClients: false,

		EnforcePKCE:                    true,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
	}

	//Repository
	requestRepository := repository.NewAuthRequestRepository(db)
	logRepository := repository.NewAuditLogRepository(db)
	jtiRepository := repository.NewBlacklistedJTIRepository(db)
	tenantRepository := repository.NewTenantRepository(db)
	webhookRepository := repository.NewWebhookRepository(db)
	clientRepository := repository.NewOAuth2ClientRepository(db)
	samlClientRepository := repository.NewSAMLClientRepository(db)
	sessionRepository := repository.NewOAuth2SessionRepository(db)
	connectionRepository := repository.NewOIDCConnectionRepository(db)
	samlConnectionRepository := repository.NewSAMLConnectionRepository(db)
	replayRepository := repository.NewSAMLReplayRepository(db)
	eventRepository := repository.NewWebhookEventRepository(db)
	healthRepository := repository.NewHealthRepository(db)
	scopeRepository := repository.NewScopeRepository(db)
	keyRepository := repository.NewCryptoKeyRepository(db)
	policyRepository := repository.NewOutboundPolicyRepository(db)

	auditLogger := audit.NewAuditLogger(db)

	iam.NewFositeStore(db, clientRepository, jtiRepository)
	fositeSecretHasher := iam.NewFositeSecretHasher(fositeConfig)

	keyMgr := utils2.NewKeyManager(keyRepository, cfg)
	federationStateProvider := security.NewFederationStateProvider(cfg)

	startupCtx := context.Background()
	if _, _, err := keyMgr.GetActivePrivateKey(startupCtx, "sig"); err != nil {
		logger.Log.Fatal("Failed to seed/load signing (sig) key", zap.Error(err))
	}
	if _, _, err := keyMgr.GetActivePrivateKey(startupCtx, "enc"); err != nil {
		logger.Log.Fatal("Failed to seed/load encryption (enc) key", zap.Error(err))
	}

	// UseCase
	provider := utils2.NewProvider(db, fositeConfig, keyMgr, clientRepository, jtiRepository)
	outboundGuard := security.NewOutboundGuard(policyRepository, cfg.SkipTLSVerify)
	auth2ClientUseCase := usecase.NewOAuth2ClientUseCase(clientRepository, connectionRepository, tenantRepository, auditLogger, fositeSecretHasher, keyMgr, outboundGuard, cfg)
	authUseCase := usecase.NewAuthUseCase(requestRepository, auditLogger)
	tenantUseCase := usecase.NewTenantUseCase(tenantRepository, auditLogger, scopeRepository)
	auditUseCase := usecase.NewAuditUseCase(logRepository)
	clientUseCase := usecase.NewSAMLClientUseCase(samlClientRepository, tenantRepository, auditLogger, outboundGuard)
	scopeUseCase := usecase.NewScopeUseCase(scopeRepository, auditLogger)
	connectionUseCase := usecase.NewOIDCConnectionUseCase(connectionRepository, auditLogger, scopeUseCase, outboundGuard)
	samlConnectionUseCase := usecase.NewSAMLConnectionUseCase(samlConnectionRepository, auditLogger, scopeUseCase, outboundGuard)
	ldapConnectionRepository := repository.NewLDAPConnectionRepository(db, []byte(cfg.AppSecret))
	ldapDialer := ldapadapter.NewLDAPDialer()
	ldapConnectionUseCase := usecase.NewLDAPConnectionUseCase(ldapConnectionRepository, ldapDialer, auditLogger, scopeUseCase, outboundGuard)
	managementUseCase := usecase.NewManagementUseCase(cfg, requestRepository, connectionRepository, samlConnectionRepository)
	sessionUseCase := usecase.NewOAuth2SessionUseCase(sessionRepository, auditLogger)
	webhookUseCase := usecase.NewWebhookUseCase(webhookRepository, eventRepository, auditLogger, outboundGuard)
	builderUseCase := usecase.NewSamlBuilderUseCase(samlClientRepository, samlConnectionRepository, replayRepository, keyMgr, cfg, federationStateProvider)
	healthUseCase := usecase.NewHealthUseCase(healthRepository)
	outboundPolicyUseCase := usecase.NewOutboundPolicyUseCase(policyRepository, auditLogger)

	publicRouter, adminRouter := router.SetupRouter(auth2ClientUseCase, authUseCase, tenantUseCase, auditUseCase, clientUseCase,
		connectionUseCase, samlConnectionUseCase, ldapConnectionUseCase, managementUseCase, sessionUseCase, webhookUseCase, builderUseCase, healthUseCase,
		scopeUseCase, outboundPolicyUseCase, outboundGuard, auditLogger, fositeConfig, cfg, provider, keyMgr, federationStateProvider)

	worker.StartCleanupJob(db, keyMgr)
	swaggerRouter := router.SetupSwaggerRouter()

	publicSrv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           publicRouter,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	adminSrv := &http.Server{
		Addr:              ":" + cfg.AdminPort,
		Handler:           adminRouter,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	swaggerSrv := &http.Server{
		Addr:              ":" + cfg.SwaggerPort,
		Handler:           swaggerRouter,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		logger.Log.Info("Starting Public Server", zap.String("port", cfg.Port))
		if err := publicSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	})

	g.Go(func() error {
		logger.Log.Info("Starting Admin Server", zap.String("port", cfg.AdminPort))
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	})

	g.Go(func() error {
		logger.Log.Info("Starting Swagger Documentation Server", zap.String("port", cfg.SwaggerPort))
		if err := swaggerSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	})

	g.Go(func() error {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

		select {
		case <-quit:
			logger.Log.Info("Shutting down servers (Signal received)...")
		case <-ctx.Done():
			logger.Log.Info("Shutting down servers (Context cancelled)...")
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := publicSrv.Shutdown(shutdownCtx); err != nil {
			logger.Log.Error("Public server forced to shutdown", zap.Error(err))
		}
		if err := adminSrv.Shutdown(shutdownCtx); err != nil {
			logger.Log.Error("Admin server forced to shutdown", zap.Error(err))
		}
		if err := swaggerSrv.Shutdown(shutdownCtx); err != nil {
			logger.Log.Error("Swagger server forced to shutdown", zap.Error(err))
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		logger.Log.Fatal("Server exit with error", zap.Error(err))
	}
}
