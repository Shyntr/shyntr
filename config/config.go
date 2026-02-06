package config

import (
	"log"
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	DSN            string   `mapstructure:"DSN"`          // Primary (Hydra style)
	DatabaseURL    string   `mapstructure:"DATABASE_URL"` // Fallback
	Port           string   `mapstructure:"PORT"`
	AppSecret      string   `mapstructure:"APP_SECRET"`
	IssuerURL      string   `mapstructure:"ISSUER_URL"`
	CookieSecure   bool     `mapstructure:"COOKIE_SECURE"`
	AllowedOrigins []string `mapstructure:"CORS_ALLOWED_ORIGINS"`
}

func LoadConfig() *Config {
	viper.SetDefault("PORT", "8080")
	// Default DSN format matches Ory standards
	viper.SetDefault("DSN", "postgres://postgres:postgres@localhost:5432/shyntr?sslmode=disable")
	viper.SetDefault("APP_SECRET", "change-me-please-very-secret-key-32-bytes")
	viper.SetDefault("ISSUER_URL", "http://localhost:8080")
	viper.SetDefault("COOKIE_SECURE", false)
	viper.SetDefault("CORS_ALLOWED_ORIGINS", []string{"*"}) // Allow all by default for dev

	viper.BindEnv("DSN")
	viper.BindEnv("DATABASE_URL")
	viper.BindEnv("PORT")
	viper.BindEnv("APP_SECRET")
	viper.BindEnv("ISSUER_URL")
	viper.BindEnv("COOKIE_SECURE")
	viper.BindEnv("CORS_ALLOWED_ORIGINS")

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Logic to fallback if DSN is missing but DATABASE_URL exists
	if cfg.DSN == "" && cfg.DatabaseURL != "" {
		cfg.DSN = cfg.DatabaseURL
	}

	// If DSN is set via strict ENV var not picked up by viper automapping in some cases
	if envDSN := os.Getenv("DSN"); envDSN != "" {
		cfg.DSN = envDSN
	}

	return &cfg
}
