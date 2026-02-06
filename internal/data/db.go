package data

import (
	"log"
	"time"

	"github.com/nevzatcirak/shyntr/internal/data/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// ConnectDB establishes a connection to PostgreSQL using the DSN.
func ConnectDB(dsn string) (*gorm.DB, error) {
	if dsn == "" {
		log.Fatal("DSN (Database Source Name) is empty. Please set DSN environment variable.")
	}

	// GORM's postgres driver handles the URL format (postgres://...) natively
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Enable pgcrypto for UUID generation
	db.Exec("CREATE EXTENSION IF NOT EXISTS pgcrypto")

	// Configure Connection Pooling
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// AutoMigrate tables
	err = db.AutoMigrate(
		&models.User{},
		&models.OAuth2Client{},
		&models.SAMLConnection{},
		&models.OAuth2Session{},
	)
	if err != nil {
		return nil, err
	}

	return db, nil
}
