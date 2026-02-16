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
	"github.com/nevzatcirak/shyntr/internal/api/router"
	"github.com/nevzatcirak/shyntr/internal/core/auth"
	"github.com/nevzatcirak/shyntr/internal/core/worker"
	"github.com/nevzatcirak/shyntr/internal/data"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/crypto"
	"github.com/nevzatcirak/shyntr/pkg/logger"
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
			db, err := data.ConnectDB(cfg)
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
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			tenant := models.Tenant{ID: args[0], Name: args[1], DisplayName: args[1], Description: "CLI Created"}
			if err := db.Create(&tenant).Error; err != nil {
				log.Fatalf("Failed: %v", err)
			}
			log.Printf("Tenant created: %s", tenant.ID)
		},
	}

	var getTenantCmd = &cobra.Command{
		Use:   "get-tenant [id]",
		Short: "Get tenant details",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			var tenant models.Tenant
			if err := db.First(&tenant, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Tenant not found: %v", err)
			}
			printJSON(tenant)
		},
	}

	var updateTenantCmd = &cobra.Command{
		Use:   "update-tenant [id] [new_name]",
		Short: "Update tenant name",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			if err := db.Model(&models.Tenant{}).Where("id = ?", args[0]).Update("name", args[1]).Error; err != nil {
				log.Fatalf("Update failed: %v", err)
			}
			log.Println("Tenant updated.")
		},
	}

	var deleteTenantCmd = &cobra.Command{
		Use:   "delete-tenant [id]",
		Short: "Delete a tenant (Cannot delete 'default')",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if args[0] == "default" {
				log.Fatal("Cannot delete default tenant via CLI")
			}
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			if err := db.Delete(&models.Tenant{}, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Delete failed: %v", err)
			}
			log.Println("Tenant deleted.")
		},
	}

	// ==========================================
	// OIDC CLIENT COMMANDS
	// ==========================================

	var createClientCmd = &cobra.Command{
		Use:   "create-client [tenant_id] [client_id] [name] [secret]",
		Short: "Create OIDC Client",
		Args:  cobra.ExactArgs(4),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			hashedSecret, _ := crypto.HashPassword(args[3])
			client := models.OAuth2Client{
				ID:                      args[1],
				TenantID:                args[0],
				Name:                    args[2],
				Secret:                  hashedSecret,
				RedirectURIs:            []string{"http://localhost:8080/callback"},
				GrantTypes:              []string{"authorization_code", "refresh_token", "client_credentials"},
				ResponseTypes:           []string{"code", "token", "id_token"},
				Scopes:                  []string{"openid", "profile", "email", "offline_access"},
				TokenEndpointAuthMethod: "client_secret_basic",
			}

			if err := db.Create(&client).Error; err != nil {
				log.Fatalf("Failed: %v", err)
			}
			log.Printf("Client created: %s", client.ID)
		},
	}

	var getClientCmd = &cobra.Command{
		Use:   "get-client [client_id]",
		Short: "Get OIDC Client details",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			var client models.OAuth2Client
			if err := db.First(&client, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Client not found: %v", err)
			}
			client.Secret = "*****" // Maskele
			printJSON(client)
		},
	}

	var updateClientCmd = &cobra.Command{
		Use:   "update-client [client_id] [new_name]",
		Short: "Update OIDC Client Name (ID remains unchanged)",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			if err := db.Model(&models.OAuth2Client{}).Where("id = ?", args[0]).Update("name", args[1]).Error; err != nil {
				log.Fatalf("Update failed: %v", err)
			}
			log.Println("Client name updated.")
		},
	}

	var deleteClientCmd = &cobra.Command{
		Use:   "delete-client [client_id]",
		Short: "Delete OIDC Client",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			if err := db.Delete(&models.OAuth2Client{}, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Delete failed: %v", err)
			}
			log.Println("Client deleted.")
		},
	}

	// ==========================================
	// SAML CLIENT COMMANDS (SP)
	// ==========================================

	var createSAMLClientCmd = &cobra.Command{
		Use:   "create-saml-client [tenant_id] [name] [entity_id] [acs_url]",
		Short: "Create SAML Service Provider",
		Args:  cobra.ExactArgs(4),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}

			client := models.SAMLClient{
				TenantID:      args[0],
				Name:          args[1],
				EntityID:      args[2],
				ACSURL:        args[3],
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

	var getSAMLClientCmd = &cobra.Command{
		Use:   "get-saml-client [entity_id]",
		Short: "Get SAML Client by EntityID",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			var client models.SAMLClient
			if err := db.First(&client, "entity_id = ?", args[0]).Error; err != nil {
				log.Fatalf("Client not found: %v", err)
			}
			printJSON(client)
		},
	}

	var updateSAMLClientCmd = &cobra.Command{
		Use:   "update-saml-client [entity_id] [new_acs_url]",
		Short: "Update SAML Client ACS URL",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			if err := db.Model(&models.SAMLClient{}).Where("entity_id = ?", args[0]).Update("acs_url", args[1]).Error; err != nil {
				log.Fatalf("Update failed: %v", err)
			}
			log.Println("SAML Client ACS URL updated.")
		},
	}

	var deleteSAMLClientCmd = &cobra.Command{
		Use:   "delete-saml-client [entity_id]",
		Short: "Delete SAML Client",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			if err := db.Where("entity_id = ?", args[0]).Delete(&models.SAMLClient{}).Error; err != nil {
				log.Fatalf("Delete failed: %v", err)
			}
			log.Println("SAML Client deleted.")
		},
	}

	// ==========================================
	// SAML CONNECTION COMMANDS (IDP)
	// ==========================================

	var createSAMLConnectionCmd = &cobra.Command{
		Use:   "create-saml-connection [tenant_id] [name] [metadata_file_path]",
		Short: "Register SAML IDP Connection",
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			xmlBytes, _ := os.ReadFile(args[2])
			meta := &saml.EntityDescriptor{}
			_ = xml.Unmarshal(xmlBytes, meta)
			conn := models.SAMLConnection{
				TenantID:       args[0],
				Name:           args[1],
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

	var getSAMLConnectionCmd = &cobra.Command{
		Use:   "get-saml-connection [id]",
		Short: "Get SAML Connection details",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			var conn models.SAMLConnection
			if err := db.First(&conn, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Connection not found: %v", err)
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
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			if err := db.Delete(&models.SAMLConnection{}, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Delete failed: %v", err)
			}
			log.Println("SAML Connection deleted.")
		},
	}

	// ==========================================
	// OIDC CONNECTION COMMANDS (External IDP)
	// ==========================================

	var createOIDCConnectionCmd = &cobra.Command{
		Use:   "create-oidc-connection [tenant_id] [name] [issuer_url] [client_id] [client_secret]",
		Short: "Register OIDC Provider",
		Args:  cobra.ExactArgs(5),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			conn := models.OIDCConnection{
				TenantID:     args[0],
				Name:         args[1],
				IssuerURL:    args[2],
				ClientID:     args[3],
				ClientSecret: args[4],
				Active:       true,
				Scopes:       []string{"openid", "profile", "email"},
			}

			if err := db.Create(&conn).Error; err != nil {
				log.Fatalf("Failed: %v", err)
			}
			log.Printf("OIDC Connection created: %s", conn.Name)
		},
	}

	var getOIDCConnectionCmd = &cobra.Command{
		Use:   "get-oidc-connection [id]",
		Short: "Get OIDC Connection details",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			var conn models.OIDCConnection
			if err := db.First(&conn, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Connection not found: %v", err)
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
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}
			if err := db.Delete(&models.OIDCConnection{}, "id = ?", args[0]).Error; err != nil {
				log.Fatalf("Delete failed: %v", err)
			}
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

	db, err := data.ConnectDB(cfg)
	if err != nil {
		logger.Log.Fatal("Database connection failed", zap.Error(err))
	}

	worker.StartCleanupJob(db)

	keyMgr := auth.NewKeyManager(db, cfg)
	_ = keyMgr.GetActivePrivateKey()

	provider := auth.NewProvider(db, []byte(cfg.AppSecret), cfg.BaseIssuerURL, keyMgr)

	publicRouter, adminRouter := router.SetupRouters(db, provider, cfg, keyMgr)

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
