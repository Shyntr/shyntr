package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lib/pq"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/api/router"
	"github.com/nevzatcirak/shyntr/internal/core/auth"
	"github.com/nevzatcirak/shyntr/internal/data"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/crypto"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func main() {
	// Initialize Structured Logger
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

	var createClientCmd = &cobra.Command{
		Use:   "create-client [id] [secret]",
		Short: "Create a new OAuth2 Client",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			createClient(args[0], args[1])
		},
	}

	var listClientsCmd = &cobra.Command{
		Use:   "list-clients",
		Short: "List all registered OAuth2 Clients",
		Run: func(cmd *cobra.Command, args []string) {
			listClients()
		},
	}

	var deleteClientCmd = &cobra.Command{
		Use:   "delete-client [id]",
		Short: "Delete an OAuth2 Client by ID",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			deleteClient(args[0])
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
	rootCmd.AddCommand(createClientCmd)
	rootCmd.AddCommand(listClientsCmd)
	rootCmd.AddCommand(deleteClientCmd)
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
		logger.Log.Error("Database connection failed", zap.Error(err))
	}

	var authProvider *auth.Provider
	if db != nil {
		authProvider = auth.NewProvider(db, []byte(cfg.AppSecret), cfg.IssuerURL)
	}

	r := router.SetupRoutes(db, authProvider, cfg)

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

// --- CLI Handlers ---

func createClient(id, secret string) {
	db := getDBConnection()
	hashedSecret, err := crypto.HashPassword(secret)
	if err != nil {
		logger.Log.Fatal("Failed to hash secret", zap.Error(err))
	}

	client := models.OAuth2Client{
		ID:            id,
		Secret:        hashedSecret,
		RedirectURIs:  pq.StringArray{"http://localhost:8080/callback", "https://oauth.tools/callback/code"},
		GrantTypes:    pq.StringArray{"authorization_code", "refresh_token", "client_credentials"},
		ResponseTypes: pq.StringArray{"code", "token", "id_token"},
		Scopes:        pq.StringArray{"openid", "offline", "profile", "email"},
		Public:        false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := db.Save(&client).Error; err != nil {
		logger.Log.Fatal("Failed to create client", zap.Error(err))
	}
	logger.Log.Info("Client created", zap.String("client_id", id))
}

func listClients() {
	db := getDBConnection()
	var clients []models.OAuth2Client
	if err := db.Find(&clients).Error; err != nil {
		logger.Log.Fatal("Failed to list clients", zap.Error(err))
	}

	fmt.Printf("%-20s | %-10s | %s\n", "CLIENT ID", "PUBLIC", "REDIRECT URIS")
	fmt.Println("---------------------------------------------------------------")
	for _, c := range clients {
		fmt.Printf("%-20s | %-10v | %v\n", c.ID, c.Public, c.RedirectURIs)
	}
}

func deleteClient(id string) {
	db := getDBConnection()
	result := db.Delete(&models.OAuth2Client{}, "id = ?", id)
	if result.Error != nil {
		logger.Log.Fatal("Failed to delete client", zap.Error(result.Error))
	}
	if result.RowsAffected == 0 {
		logger.Log.Warn("Client not found", zap.String("client_id", id))
	} else {
		logger.Log.Info("Client deleted", zap.String("client_id", id))
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
	// Re-init logger for CLI if needed separately, but main calls it
	cfg := config.LoadConfig()
	db, err := data.ConnectDB(cfg.DSN)
	if err != nil {
		logger.Log.Fatal("Database connection failed", zap.Error(err))
	}
	return db
}
