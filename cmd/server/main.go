package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/crewjam/saml"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/adapters/audit"
	router "github.com/nevzatcirak/shyntr/internal/adapters/http"
	"github.com/nevzatcirak/shyntr/internal/adapters/iam"
	persistence "github.com/nevzatcirak/shyntr/internal/adapters/persistence"
	"github.com/nevzatcirak/shyntr/internal/adapters/persistence/models"
	"github.com/nevzatcirak/shyntr/internal/adapters/persistence/repository"
	"github.com/nevzatcirak/shyntr/internal/application/usecase"
	utils2 "github.com/nevzatcirak/shyntr/internal/application/utils"
	"github.com/nevzatcirak/shyntr/internal/application/worker"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
	shcrypto "github.com/nevzatcirak/shyntr/pkg/crypto"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/nevzatcirak/shyntr/pkg/utils"
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

	// CREATE TENANT
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
				tenantID, _ = utils.GenerateRandomHex(4) // Random ID if empty
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
				log.Fatalf("Delete failed: %v", err)
			}
			auditLogger.Log(args[0], "system_cli", "cli.tenant.delete", "127.0.0.1", "shyntr-cli", map[string]interface{}{
				"tenant_id": args[0],
			})
			log.Println("Tenant deleted.")
		},
	}

	// ==========================================
	// OIDC CLIENT COMMANDS
	// ==========================================

	// CREATE CLIENT
	var (
		clientID, clientName, clientSecret string
		redirectURIs                       []string
		isPublic                           bool
	)
	var createClientCmd = &cobra.Command{
		Use:   "create-client",
		Short: "Create OIDC Client (Use flags)",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}

			// Defaults
			if tenantID == "" {
				tenantID = "default"
			}
			if clientID == "" {
				clientID, _ = utils.GenerateRandomHex(8)
			}
			if clientName == "" {
				clientName = "New Client " + clientID
			}
			if clientSecret == "" && !isPublic {
				clientSecret, _ = utils.GenerateRandomHex(16)
			}
			if len(redirectURIs) == 0 {
				redirectURIs = []string{"http://localhost:8080/callback"}
			}

			hashedSecret := ""
			if clientSecret != "" {
				fositeCfg := &fosite.Config{GlobalSecret: []byte(cfg.AppSecret)}
				hashedSecret, _ = shcrypto.HashSecret(context.Background(), fositeCfg, clientSecret)
			}

			authMethod := "client_secret_basic"
			if isPublic {
				authMethod = "none"
			}

			client := models.OAuth2ClientGORM{
				ID:                      clientID,
				TenantID:                tenantID,
				Name:                    clientName,
				Secret:                  hashedSecret,
				RedirectURIs:            redirectURIs,
				GrantTypes:              []string{"authorization_code", "refresh_token", "client_credentials", "implicit"},
				ResponseTypes:           []string{"code", "token", "id_token", "code id_token", "code token", "code id_token token"},
				ResponseModes:           []string{"query", "fragment", "form_post"},
				Scopes:                  []string{"openid", "profile", "email", "offline_access"},
				TokenEndpointAuthMethod: authMethod,
				Public:                  isPublic,
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
	createClientCmd.Flags().StringSliceVar(&redirectURIs, "redirect-uris", nil, "Comma separated Redirect URIs")
	createClientCmd.Flags().BoolVar(&isPublic, "public", false, "Is Public Client (SPA/Mobile)")

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
				updates["redirect_uris"] = redirectURIs
			}
			if clientSecret != "" {
				fositeCfg := &fosite.Config{GlobalSecret: []byte(cfg.AppSecret)}
				hashed, _ := shcrypto.HashSecret(context.Background(), fositeCfg, clientSecret)
				updates["secret"] = hashed
			}
			var client models.OAuth2ClientGORM
			db.Select("tenant_id").First(&client, "id = ?", args[0])
			if err := db.Model(&models.OAuth2ClientGORM{}).Where("id = ?", args[0]).Updates(updates).Error; err != nil {
				log.Fatalf("Update failed: %v", err)
			}
			auditLogger.Log(client.TenantID, "system_cli", "cli.client.oidc.update", "127.0.0.1", "shyntr-cli", map[string]interface{}{"client_id": args[0]})
			log.Println("Client updated.")
		},
	}
	updateClientCmd.Flags().StringVar(&clientName, "name", "", "New Client Name")
	updateClientCmd.Flags().StringSliceVar(&redirectURIs, "redirect-uris", nil, "New Redirect URIs")
	updateClientCmd.Flags().StringVar(&clientSecret, "secret", "", "New Client Secret")

	var deleteClientCmd = &cobra.Command{
		Use:   "delete-client [client_id]",
		Short: "Delete OIDC Client",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			auditLogger := audit.NewAuditLogger(db)
			var client models.OAuth2ClientGORM
			db.Select("tenant_id").First(&client, "id = ?", args[0])
			if err := db.Delete(&models.OAuth2ClientGORM{}, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Delete failed: %v", err)
			}
			auditLogger.Log(client.TenantID, "system_cli", "cli.client.oidc.delete", "127.0.0.1", "shyntr-cli", map[string]interface{}{"client_id": args[0]})
			log.Println("Client deleted.")
		},
	}

	// ==========================================
	// SAML CLIENT COMMANDS (SP)
	// ==========================================

	var (
		samlEntityID, samlACSURL string
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
				Active:        true,
				SignResponse:  true,
				SignAssertion: true,
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
			if clientName != "" {
				updates["name"] = clientName
			}

			if len(updates) == 0 {
				log.Println("No changes detected.")
				return
			}
			var client models.SAMLClientGORM
			db.Select("tenant_id").First(&client, "entity_id = ?", args[0])
			if err := db.Model(&models.SAMLClientGORM{}).Where("entity_id = ?", args[0]).Updates(updates).Error; err != nil {
				log.Fatalf("Update failed: %v", err)
			}
			auditLogger.Log(client.TenantID, "system_cli", "cli.client.saml.update", "127.0.0.1", "shyntr-cli", map[string]interface{}{"entity_id": args[0]})
			log.Println("SAML Client updated.")
		},
	}
	updateSAMLClientCmd.Flags().StringVar(&samlACSURL, "acs-url", "", "New ACS URL")
	updateSAMLClientCmd.Flags().StringVar(&clientName, "name", "", "New App Name")

	var deleteSAMLClientCmd = &cobra.Command{
		Use:   "delete-saml-client [entity_id]",
		Short: "Delete SAML Client",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("DB Error: %v", err)
			}
			auditLogger := audit.NewAuditLogger(db)
			var client models.SAMLClientGORM
			db.Select("tenant_id").First(&client, "entity_id = ?", args[0])
			if err := db.Where("entity_id = ?", args[0]).Delete(&models.SAMLClientGORM{}).Error; err != nil {
				log.Fatalf("Delete Failed: %v", err)
			}
			auditLogger.Log(client.TenantID, "system_cli", "cli.client.saml.delete", "127.0.0.1", "shyntr-cli", map[string]interface{}{"entity_id": args[0]})
			log.Println("SAML Client deleted.")
		},
	}

	// ==========================================
	// SAML CONNECTION COMMANDS (IDP)
	// ==========================================

	var metadataFile string
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
			if metadataFile == "" {
				log.Fatal("--metadata-file is required")
			}
			if clientName == "" {
				clientName = "SAML IDP"
			}

			xmlBytes, err := os.ReadFile(metadataFile)
			if err != nil {
				log.Fatalf("Failed to read metadata file: %v", err)
			}

			meta := &saml.EntityDescriptor{}
			_ = xml.Unmarshal(xmlBytes, meta)
			conn := models.SAMLConnectionGORM{
				TenantID:       tenantID,
				Name:           clientName,
				IdpMetadataXML: string(xmlBytes),
				IdpEntityID:    meta.EntityID,
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
		Short: "Delete SAML Connection",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("DB Error: %v", err)
			}
			auditLogger := audit.NewAuditLogger(db)
			var conn models.SAMLConnectionGORM
			db.Select("tenant_id").First(&conn, "id = ?", args[0])
			if err := db.Delete(&models.SAMLConnectionGORM{}, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Delete Failed: %v", err)
			}
			auditLogger.Log(conn.TenantID, "system_cli", "cli.connection.saml.delete", "127.0.0.1", "shyntr-cli", map[string]interface{}{"connection_id": args[0]})
			log.Println("SAML Connection deleted.")
		},
	}

	// ==========================================
	// OIDC CONNECTION COMMANDS (External IDP)
	// ==========================================

	var issuerURL string
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

			conn := models.OIDCConnectionGORM{
				TenantID:     tenantID,
				Name:         clientName,
				IssuerURL:    issuerURL,
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Active:       true,
				Scopes:       []string{"openid", "profile", "email"},
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
		Short: "Delete OIDC Connection",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := persistence.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("DB Error: %v", err)
			}
			auditLogger := audit.NewAuditLogger(db)
			var conn models.OIDCConnectionGORM
			db.Select("tenant_id").First(&conn, "id = ?", args[0])
			if err := db.Delete(&models.OIDCConnectionGORM{}, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Delete Failed: %v", err)
			}
			auditLogger.Log(conn.TenantID, "system_cli", "cli.connection.oidc.delete", "127.0.0.1", "shyntr-cli", map[string]interface{}{"connection_id": args[0]})
			log.Println("OIDC Connection deleted.")
		},
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
		createClientCmd, getClientCmd, updateClientCmd, deleteClientCmd,
		createSAMLClientCmd, getSAMLClientCmd, updateSAMLClientCmd, deleteSAMLClientCmd,
		createSAMLConnectionCmd, getSAMLConnectionCmd, deleteSAMLConnectionCmd,
		createOIDCConnectionCmd, getOIDCConnectionCmd, deleteOIDCConnectionCmd,
		serveCmd,
	)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runServer() {
	cfg := config.LoadConfig()
	logger.InitLogger(cfg.LogLevel)

	db, err := persistence.ConnectDB(cfg)
	if err != nil {
		logger.Log.Fatal("Database connection failed", zap.Error(err))
	}

	var count int64
	if err := db.Model(&entity.Tenant{}).Where("id = ?", cfg.DefaultTenantID).Count(&count).Error; err == nil && count == 0 {
		logger.Log.Info("Default tenant not found, creating...", zap.String("id", cfg.DefaultTenantID))
		persistence.SeedDefaultTenant(db, cfg)
	}
	worker.StartCleanupJob(db)

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

	auditLogger := audit.NewAuditLogger(db)

	iam.NewFositeStore(db, clientRepository, jtiRepository)
	fositeSecretHasher := iam.NewFositeSecretHasher(fositeConfig)

	//UseCase
	provider := utils2.NewProvider(db, fositeConfig, keyMgr, clientRepository, jtiRepository)
	auth2ClientUseCase := usecase.NewOAuth2ClientUseCase(clientRepository, connectionRepository, tenantRepository, auditLogger, fositeSecretHasher, keyMgr, cfg)
	authUseCase := usecase.NewAuthUseCase(requestRepository, auditLogger)
	tenantUseCase := usecase.NewTenantUseCase(tenantRepository, auditLogger, scopeRepository)
	auditUseCase := usecase.NewAuditUseCase(logRepository)
	clientUseCase := usecase.NewSAMLClientUseCase(samlClientRepository, tenantRepository, auditLogger)
	scopeUseCase := usecase.NewScopeUseCase(scopeRepository, auditLogger)
	connectionUseCase := usecase.NewOIDCConnectionUseCase(connectionRepository, auditLogger, scopeUseCase)
	samlConnectionUseCase := usecase.NewSAMLConnectionUseCase(samlConnectionRepository, auditLogger, scopeUseCase)
	managementUseCase := usecase.NewManagementUseCase(cfg, requestRepository, connectionRepository, samlConnectionRepository)
	sessionUseCase := usecase.NewOAuth2SessionUseCase(sessionRepository, auditLogger)
	webhookUseCase := usecase.NewWebhookUseCase(webhookRepository, eventRepository, auditLogger)
	builderUseCase := usecase.NewSamlBuilderUseCase(samlClientRepository, samlConnectionRepository, replayRepository, keyMgr, cfg)
	healthUseCase := usecase.NewHealthUseCase(healthRepository)

	publicRouter, adminRouter := router.SetupRouter(auth2ClientUseCase, authUseCase, tenantUseCase, auditUseCase, clientUseCase,
		connectionUseCase, samlConnectionUseCase, managementUseCase, sessionUseCase, webhookUseCase, builderUseCase, healthUseCase,
		scopeUseCase, fositeConfig, cfg, provider, keyMgr)

	publicSrv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: publicRouter,
	}

	adminSrv := &http.Server{
		Addr:    ":" + cfg.AdminPort,
		Handler: adminRouter,
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
		return nil
	})

	if err := g.Wait(); err != nil {
		logger.Log.Fatal("Server exit with error", zap.Error(err))
	}
}
