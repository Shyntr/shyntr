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
	AdminPort           string   `mapstructure:"ADMIN_PORT"`
	AppSecret           string   `mapstructure:"APP_SECRET"`
	BaseIssuerURL       string   `mapstructure:"ISSUER_URL"`
	CookieSecure        bool     `mapstructure:"COOKIE_SECURE"`
	AllowedOrigins      []string `mapstructure:"CORS_ALLOWED_ORIGINS"`
	AdminAllowedOrigins []string `mapstructure:"ADMIN_CORS_ALLOWED_ORIGINS"`
	RSAPrivateKeyBase64 string   `mapstructure:"APP_PRIVATE_KEY_BASE64"`
	LogLevel            string   `mapstructure:"LOG_LEVEL"`

	// Security Tuning
	SkipTLSVerify bool `mapstructure:"SKIP_TLS_VERIFY"`

	// Database Connection Pool
	DBMaxIdleConns int `mapstructure:"DB_MAX_IDLE_CONNS"`
	DBMaxOpenConns int `mapstructure:"DB_MAX_OPEN_CONNS"`

	// External UI URLs
	ExternalLoginURL   string `mapstructure:"EXTERNAL_LOGIN_URL"`
	ExternalConsentURL string `mapstructure:"EXTERNAL_CONSENT_URL"`

	// Multi-Tenancy
	DefaultTenantID string `mapstructure:"DEFAULT_TENANT_ID"`

	AccessTokenLifespan  string `mapstructure:"ACCESS_TOKEN_LIFESPAN"`
	RefreshTokenLifespan string `mapstructure:"REFRESH_TOKEN_LIFESPAN"`
	IDTokenLifespan      string `mapstructure:"ID_TOKEN_LIFESPAN"`
}

func LoadConfig() *Config {
	viper.SetDefault("PORT", "7496")
	viper.SetDefault("ADMIN_PORT", "7497")
	viper.SetDefault("DSN", "postgres://shyntr:secretpassword@localhost:5432/shyntr?sslmode=disable")
	viper.SetDefault("APP_SECRET", "12345678901234567890123456789012")

	viper.SetDefault("ISSUER_URL", "http://localhost:7496")

	viper.SetDefault("COOKIE_SECURE", false)
	viper.SetDefault("CORS_ALLOWED_ORIGINS", []string{"http://localhost:3010", "http://localhost:3000", "http://localhost:3274"})
	viper.SetDefault("ADMIN_CORS_ALLOWED_ORIGINS", []string{"http://localhost:3010", "http://localhost:3000", "http://localhost:3274", "http://localhost:7497"})

	viper.SetDefault("EXTERNAL_LOGIN_URL", "http://localhost:3000/login")
	viper.SetDefault("EXTERNAL_CONSENT_URL", "http://localhost:3000/consent")

	viper.SetDefault("DEFAULT_TENANT_ID", "default")

	viper.SetDefault("ACCESS_TOKEN_LIFESPAN", "1h")
	viper.SetDefault("REFRESH_TOKEN_LIFESPAN", "720h")
	viper.SetDefault("ID_TOKEN_LIFESPAN", "1h")

	viper.SetDefault("LOG_LEVEL", "info")

	// Security Defaults
	viper.SetDefault("SKIP_TLS_VERIFY", false)

	viper.SetDefault("DB_MAX_IDLE_CONNS", 10)
	viper.SetDefault("DB_MAX_OPEN_CONNS", 100)

	mustBind(consts.EnvDatabaseDSN)
	mustBind("DATABASE_URL")
	mustBind("PORT")
	mustBind("ADMIN_PORT")
	mustBind(consts.EnvAppSecret)
	mustBind("ISSUER_URL")
	mustBind("COOKIE_SECURE")
	mustBind("CORS_ALLOWED_ORIGINS")
	mustBind("ADMIN_CORS_ALLOWED_ORIGINS")
	mustBind(consts.EnvRSAPrivateKey)
	mustBind("EXTERNAL_LOGIN_URL")
	mustBind("EXTERNAL_CONSENT_URL")
	mustBind("DEFAULT_TENANT_ID")
	mustBind("ACCESS_TOKEN_LIFESPAN")
	mustBind("REFRESH_TOKEN_LIFESPAN")
	mustBind("ID_TOKEN_LIFESPAN")
	mustBind("LOG_LEVEL")
	mustBind("SKIP_TLS_VERIFY")
	mustBind("DB_MAX_IDLE_CONNS")
	mustBind("DB_MAX_OPEN_CONNS")

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
