package main

import (
	"encoding/xml"
	"log"
	"os"

	"github.com/crewjam/saml"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/api/router"
	"github.com/nevzatcirak/shyntr/internal/core/auth"
	"github.com/nevzatcirak/shyntr/internal/data"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "shyntr",
		Short: "Shyntr - Identity & Access Management",
	}

	var migrateCmd = &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg.DSN)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			if err := data.MigrateDB(db); err != nil {
				log.Fatalf("Migration failed: %v", err)
			}
			log.Println("Database migration completed successfully.")
		},
	}

	var createTenantCmd = &cobra.Command{
		Use:   "create-tenant [id] [name]",
		Short: "Create a new tenant",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg.DSN)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}

			tenant := models.Tenant{ID: args[0], Name: args[1]}
			if err := db.Create(&tenant).Error; err != nil {
				log.Fatalf("Failed to create tenant: %v", err)
			}
			log.Printf("Tenant created: %s (%s)", tenant.Name, tenant.ID)
		},
	}

	var createClientCmd = &cobra.Command{
		Use:   "create-client [tenant_id] [client_id] [secret]",
		Short: "Create a new OAuth2 Client",
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg.DSN)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}

			client := models.OAuth2Client{
				ID:            args[1],
				Secret:        args[2], // In production, hash this!
				TenantID:      args[0],
				RedirectURIs:  []string{"http://localhost:8080/callback"},
				GrantTypes:    []string{"authorization_code", "refresh_token", "client_credentials"},
				ResponseTypes: []string{"code", "token", "id_token"},
				Scopes:        []string{"openid", "profile", "email", "offline_access"},
			}

			if err := db.Create(&client).Error; err != nil {
				log.Fatalf("Failed to create client: %v", err)
			}
			log.Printf("Client created: %s for tenant %s", client.ID, client.TenantID)
		},
	}

	var createSAMLConnectionCmd = &cobra.Command{
		Use:   "create-saml [tenant_id] [name] [metadata_file_path]",
		Short: "Register a SAML IDP connection from a metadata XML file",
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg.DSN)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}

			tenantID := args[0]
			name := args[1]
			filePath := args[2]

			xmlBytes, err := os.ReadFile(filePath)
			if err != nil {
				log.Fatalf("Failed to read metadata file: %v", err)
			}

			meta := &saml.EntityDescriptor{}
			if err := xml.Unmarshal(xmlBytes, meta); err != nil {
				log.Fatalf("Invalid SAML Metadata XML: %v", err)
			}
			entityID := meta.EntityID
			log.Printf("Detected IDP EntityID: %s", entityID)

			conn := models.SAMLConnection{
				TenantID:       tenantID,
				Name:           name,
				IdpMetadataXML: string(xmlBytes),
				IdpEntityID:    entityID,
				Active:         true,
			}

			if err := db.Create(&conn).Error; err != nil {
				log.Fatalf("Failed to create SAML connection: %v", err)
			}
			log.Printf("SAML Connection created: %s (ID: %s)", conn.Name, conn.ID)
		},
	}

	var serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start the Identity Broker server",
		Run: func(cmd *cobra.Command, args []string) {
			runServer()
		},
	}

	rootCmd.AddCommand(migrateCmd, createTenantCmd, createClientCmd, createSAMLConnectionCmd, serveCmd)
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runServer() {
	logger.InitLogger()
	cfg := config.LoadConfig()

	db, err := data.ConnectDB(cfg.DSN)
	if err != nil {
		logger.Log.Fatal("Database connection failed", zap.Error(err))
	}

	keyMgr := auth.NewKeyManager(db, cfg)
	_ = keyMgr.GetActivePrivateKey()

	provider := auth.NewProvider(db, []byte(cfg.AppSecret), cfg.BaseIssuerURL, keyMgr)

	r := router.SetupRoutes(db, provider, cfg, keyMgr)

	logger.Log.Info("Starting Shyntr Broker",
		zap.String("port", cfg.Port),
		zap.String("base_issuer", cfg.BaseIssuerURL),
		zap.String("external_login", cfg.ExternalLoginURL),
		zap.String("default_tenant", cfg.DefaultTenantID),
	)

	if err := r.Run(":" + cfg.Port); err != nil {
		logger.Log.Fatal("Server failed to start", zap.Error(err))
	}
}
