package data

import (
	"log"
	"time"

	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func ConnectDB(cfg *config.Config) (*gorm.DB, error) {
	if cfg.DSN == "" {
		log.Fatal("DSN (Database Source Name) is empty.")
	}

	db, err := gorm.Open(postgres.Open(cfg.DSN), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	db.Exec("CREATE EXTENSION IF NOT EXISTS pgcrypto")

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxIdleConns(cfg.DBMaxIdleConns)
	sqlDB.SetMaxOpenConns(cfg.DBMaxOpenConns)
	sqlDB.SetConnMaxLifetime(time.Hour)

	return db, nil
}

// MigrateDB runs the schema migration.
func MigrateDB(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.Tenant{},
		&models.OAuth2Client{},
		&models.SAMLConnection{},
		&models.SAMLClient{},
		&models.SAMLReplayCache{},
		&models.OIDCConnection{},
		&models.OAuth2Session{},
		&models.SigningKey{},
		&models.LoginRequest{},
		&models.ConsentRequest{},
		&models.BlacklistedJTI{},
	)
}

func SeedDefaultTenant(db *gorm.DB, cfg *config.Config) {
	var count int64
	if err := db.Model(&models.Tenant{}).Where("id = ?", "default").Count(&count).Error; err != nil {
		logger.Log.Error("Failed to check default tenant", zap.Error(err))
		return
	}

	if count == 0 {
		defaultTenant := models.Tenant{
			ID:          cfg.DefaultTenantID,
			Name:        "default",
			DisplayName: "Default Tenant",
			Description: "This is the default (root) isolation area of the system. All applications (clients) and identity providers (connections) operate in this space unless a specific tenant (customer/domain) is designated. This tenant cannot be deleted to ensure system integrity.",
		}

		if err := db.Create(&defaultTenant).Error; err != nil {
			logger.Log.Fatal("Failed to create default tenant on startup", zap.Error(err))
			return
		}
		logger.Log.Info("Default tenant successfully seeded.")
	} else {
		logger.Log.Info("Default tenant already exists.")
	}
}
