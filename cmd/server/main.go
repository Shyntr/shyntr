package main

import (
	"context"
	"encoding/xml"
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
			db, err := data.ConnectDB(cfg)
			if err != nil {
				log.Fatalf("Database connection failed: %v", err)
			}

			hashedSecret, err := crypto.HashPassword(args[2])
			if err != nil {
				log.Fatalf("Failed to hash secret: %v", err)
			}

			client := models.OAuth2Client{
				ID:            args[1],
				Secret:        hashedSecret,
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
			db, err := data.ConnectDB(cfg)
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
