package repository

import (
	"context"

	"github.com/Shyntr/shyntr/internal/application/port"
	"gorm.io/gorm"
)

type healthRepository struct {
	db *gorm.DB
}

func NewHealthRepository(db *gorm.DB) port.HealthRepository {
	return &healthRepository{db: db}
}

func (r *healthRepository) Ping(ctx context.Context) error {
	sqlDB, err := r.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

func (r *healthRepository) VerifyMigrations(ctx context.Context) error {
	// Check for a few critical tables to ensure migrations have run.
	criticalTables := []string{
		"tenants",
		"o_auth2_clients",
		"crypto_keys",
		"audit_logs",
	}

	for _, table := range criticalTables {
		if !r.db.Migrator().HasTable(table) {
			return gorm.ErrRecordNotFound
		}
	}

	return nil
}
