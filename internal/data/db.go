package data

import (
	"log"
	"time"

	"github.com/nevzatcirak/shyntr/internal/data/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// ConnectDB establishes a connection to PostgreSQL using the DSN.
// NOTE: This does NOT auto-migrate anymore. Use MigrateDB for that.
func ConnectDB(dsn string) (*gorm.DB, error) {
	if dsn == "" {
		log.Fatal("DSN (Database Source Name) is empty.")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	db.Exec("CREATE EXTENSION IF NOT EXISTS pgcrypto")

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	return db, nil
}

// MigrateDB runs the schema migration.
// Separated for 'shyntr migrate' command.
func MigrateDB(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.User{},
		&models.OAuth2Client{},
		&models.SAMLConnection{},
		&models.OAuth2Session{},
		&models.SigningKey{}, // Added
	)
}
