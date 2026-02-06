package config

import (
	"log"
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	DSN                 string   `mapstructure:"DSN"`
	DatabaseURL         string   `mapstructure:"DATABASE_URL"`
	Port                string   `mapstructure:"PORT"`
	AppSecret           string   `mapstructure:"APP_SECRET"`
	IssuerURL           string   `mapstructure:"ISSUER_URL"`
	CookieSecure        bool     `mapstructure:"COOKIE_SECURE"`
	AllowedOrigins      []string `mapstructure:"CORS_ALLOWED_ORIGINS"`
	RSAPrivateKeyBase64 string   `mapstructure:"APP_RSA_KEY_BASE64"` // Task 3
}

func LoadConfig() *Config {
	viper.SetDefault("PORT", "8080")
	viper.SetDefault("DSN", "postgres://postgres:postgres@localhost:5432/shyntr?sslmode=disable")
	viper.SetDefault("APP_SECRET", "change-me-please-very-secret-key-32-bytes") // Must be 32 bytes for AES-256
	viper.SetDefault("ISSUER_URL", "http://localhost:8080")
	viper.SetDefault("COOKIE_SECURE", false)
	viper.SetDefault("CORS_ALLOWED_ORIGINS", []string{"*"})

	mustBind("DSN")
	mustBind("DATABASE_URL")
	mustBind("PORT")
	mustBind("APP_SECRET")
	mustBind("ISSUER_URL")
	mustBind("COOKIE_SECURE")
	mustBind("CORS_ALLOWED_ORIGINS")
	mustBind("APP_RSA_KEY_BASE64")

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if cfg.DSN == "" && cfg.DatabaseURL != "" {
		cfg.DSN = cfg.DatabaseURL
	}
	if envDSN := os.Getenv("DSN"); envDSN != "" {
		cfg.DSN = envDSN
	}

	// Ensure AppSecret is 32 bytes (pad or trim if necessary for AES)
	// In production, crash if not correct length. Here we simple check.
	if len(cfg.AppSecret) != 32 {
		// Just a warning in dev, but critical in prod
		log.Println("WARNING: APP_SECRET should be exactly 32 bytes for AES-256 security.")
	}

	return &cfg
}

func mustBind(key string) {
	if err := viper.BindEnv(key); err != nil {
		log.Printf("Warning: Failed to bind env var %s: %v", key, err)
	}
}
