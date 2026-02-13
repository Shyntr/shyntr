package data

import (
	"log"
	"time"

	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/data/models"
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
