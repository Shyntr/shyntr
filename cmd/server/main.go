package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lib/pq"
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
	"gorm.io/gorm"
)

func main() {
	logger.InitLogger()
	defer logger.Sync()

	var rootCmd = &cobra.Command{
		Use:   "shyntr",
		Short: "Shyntr - Identity & Access Management",
	}

	var serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start the Shyntr server",
		Run: func(cmd *cobra.Command, args []string) {
			runServer()
		},
	}

	var migrateCmd = &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations",
		Run: func(cmd *cobra.Command, args []string) {
			runMigrations()
		},
	}

	var createClientCmd = &cobra.Command{
		Use:   "create-client [id] [secret]",
		Short: "Create a new OAuth2 Client",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			createClient(args[0], args[1])
		},
	}

	var rotateSecretCmd = &cobra.Command{
		Use:   "rotate-secret [client_id] [new_secret]",
		Short: "Rotate Client Secret (Overwrites old one)",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			rotateClientSecret(args[0], args[1])
		},
	}

	var createUserCmd = &cobra.Command{
		Use:   "create-user [email] [password] [first_name] [last_name]",
		Short: "Create a new User",
		Args:  cobra.ExactArgs(4),
		Run: func(cmd *cobra.Command, args []string) {
			createUser(args[0], args[1], args[2], args[3])
		},
	}

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(migrateCmd)
	rootCmd.AddCommand(createClientCmd)
	rootCmd.AddCommand(rotateSecretCmd)
	rootCmd.AddCommand(createUserCmd)

	if err := rootCmd.Execute(); err != nil {
		logger.Log.Fatal("CLI execution failed", zap.Error(err))
	}
}

func runServer() {
	cfg := config.LoadConfig()
	logger.Log.Info("Starting Shyntr",
		zap.String("port", cfg.Port),
		zap.String("issuer_url", cfg.IssuerURL),
	)

	db, err := data.ConnectDB(cfg.DSN)
	if err != nil {
		logger.Log.Fatal("Database connection failed", zap.Error(err))
	}

	// Initialize Key Manager
	keyMgr := auth.NewKeyManager(db, cfg)

	// Initialize Auth Provider with Key Manager
	var authProvider *auth.Provider
	authProvider = auth.NewProvider(db, []byte(cfg.AppSecret), cfg.IssuerURL, keyMgr)

	// Start Background Worker
	worker.StartCleanupJob(db)

	r := router.SetupRoutes(db, authProvider, cfg, keyMgr)

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Log.Fatal("Listen failed", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Log.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Log.Fatal("Server forced to shutdown", zap.Error(err))
	}

	logger.Log.Info("Server exiting")
}

func runMigrations() {
	cfg := config.LoadConfig()
	db, err := data.ConnectDB(cfg.DSN)
	if err != nil {
		logger.Log.Fatal("Database connection failed", zap.Error(err))
	}
	if err := data.MigrateDB(db); err != nil {
		logger.Log.Fatal("Migration failed", zap.Error(err))
	}
	logger.Log.Info("Migrations applied successfully.")
}

func createClient(id, secret string) {
	db := getDBConnection()
	hashedSecret, err := crypto.HashPassword(secret)
	if err != nil {
		logger.Log.Fatal("Failed to hash secret", zap.Error(err))
	}

	client := models.OAuth2Client{
		ID:            id,
		Secret:        hashedSecret,
		RedirectURIs:  pq.StringArray{"http://localhost:8080/callback"},
		GrantTypes:    pq.StringArray{"authorization_code", "refresh_token"},
		ResponseTypes: pq.StringArray{"code", "token", "id_token"},
		Scopes:        pq.StringArray{"openid", "offline", "profile", "email"},
		Public:        false,
		SkipConsent:   false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := db.Save(&client).Error; err != nil {
		logger.Log.Fatal("Failed to create client", zap.Error(err))
	}
	logger.Log.Info("Client created", zap.String("client_id", id))
}

func rotateClientSecret(id, newSecret string) {
	db := getDBConnection()
	hashedSecret, err := crypto.HashPassword(newSecret)
	if err != nil {
		logger.Log.Fatal("Failed to hash secret", zap.Error(err))
	}

	result := db.Model(&models.OAuth2Client{}).Where("id = ?", id).Update("secret", hashedSecret)
	if result.Error != nil {
		logger.Log.Fatal("Failed to rotate secret", zap.Error(result.Error))
	}
	if result.RowsAffected == 0 {
		logger.Log.Warn("Client not found", zap.String("client_id", id))
	} else {
		logger.Log.Info("Client secret rotated", zap.String("client_id", id))
	}
}

func createUser(email, password, firstName, lastName string) {
	db := getDBConnection()
	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		logger.Log.Fatal("Failed to hash password", zap.Error(err))
	}

	user := models.User{
		Email:        email,
		PasswordHash: hashedPassword,
		FirstName:    firstName,
		LastName:     lastName,
		IsActive:     true,
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := db.Create(&user).Error; err != nil {
		logger.Log.Fatal("Failed to create user", zap.Error(err))
	}
	logger.Log.Info("User created", zap.String("email", email))
}

func getDBConnection() *gorm.DB {
	cfg := config.LoadConfig()
	db, err := data.ConnectDB(cfg.DSN)
	if err != nil {
		logger.Log.Fatal("Database connection failed", zap.Error(err))
	}
	return db
}
