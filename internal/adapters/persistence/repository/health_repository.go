package repository

import (
	"context"

	"github.com/nevzatcirak/shyntr/internal/application/port"
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
