package config

import (
	"log"
	"os"

	"github.com/nevzatcirak/shyntr/pkg/consts"
	"github.com/spf13/viper"
)

type Config struct {
	DSN                 string   `mapstructure:"DSN"`
	DatabaseURL         string   `mapstructure:"DATABASE_URL"`
	Port                string   `mapstructure:"PORT"`
	AppSecret           string   `mapstructure:"APP_SECRET"`
	BaseIssuerURL       string   `mapstructure:"ISSUER_URL"` // Base URL e.g. http://localhost:8080
	CookieSecure        bool     `mapstructure:"COOKIE_SECURE"`
	AllowedOrigins      []string `mapstructure:"CORS_ALLOWED_ORIGINS"`
	RSAPrivateKeyBase64 string   `mapstructure:"APP_RSA_KEY_BASE64"`

	// External UI URLs (The App that handles login/consent)
	ExternalLoginURL   string `mapstructure:"EXTERNAL_LOGIN_URL"`
	ExternalConsentURL string `mapstructure:"EXTERNAL_CONSENT_URL"`

	AccessTokenLifespan  string `mapstructure:"ACCESS_TOKEN_LIFESPAN"`
	RefreshTokenLifespan string `mapstructure:"REFRESH_TOKEN_LIFESPAN"`
	IDTokenLifespan      string `mapstructure:"ID_TOKEN_LIFESPAN"`
}

func LoadConfig() *Config {
	viper.SetDefault("PORT", "8080")
	viper.SetDefault("DSN", "postgres://postgres:postgres@localhost:5432/shyntr?sslmode=disable")
	viper.SetDefault("APP_SECRET", "change-me-please-very-secret-key-32-bytes")
	viper.SetDefault("ISSUER_URL", "http://localhost:8080")
	viper.SetDefault("COOKIE_SECURE", false)
	viper.SetDefault("CORS_ALLOWED_ORIGINS", []string{"*"})

	// Default to internal handlers for now (or a mock external app)
	viper.SetDefault("EXTERNAL_LOGIN_URL", "http://localhost:8080/auth/login")
	viper.SetDefault("EXTERNAL_CONSENT_URL", "http://localhost:8080/auth/consent")

	viper.SetDefault("ACCESS_TOKEN_LIFESPAN", "1h")
	viper.SetDefault("REFRESH_TOKEN_LIFESPAN", "720h") // 30 Days
	viper.SetDefault("ID_TOKEN_LIFESPAN", "1h")

	mustBind(consts.EnvDatabaseDSN)
	mustBind("DATABASE_URL")
	mustBind("PORT")
	mustBind(consts.EnvAppSecret)
	mustBind("ISSUER_URL")
	mustBind("COOKIE_SECURE")
	mustBind("CORS_ALLOWED_ORIGINS")
	mustBind(consts.EnvRSAPrivateKey)
	mustBind("EXTERNAL_LOGIN_URL")
	mustBind("EXTERNAL_CONSENT_URL")
	mustBind("ACCESS_TOKEN_LIFESPAN")
	mustBind("REFRESH_TOKEN_LIFESPAN")
	mustBind("ID_TOKEN_LIFESPAN")

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if cfg.DSN == "" && cfg.DatabaseURL != "" {
		cfg.DSN = cfg.DatabaseURL
	}
	if envDSN := os.Getenv(consts.EnvDatabaseDSN); envDSN != "" {
		cfg.DSN = envDSN
	}

	if len(cfg.AppSecret) != 32 {
		log.Println("WARNING: APP_SECRET should be exactly 32 bytes for AES-256 security.")
	}

	return &cfg
}

func mustBind(key string) {
	if err := viper.BindEnv(key); err != nil {
		log.Printf("Warning: Failed to bind env var %s: %v", key, err)
	}
}
