package repository

import (
	"context"

	"github.com/nevzatcirak/shyntr/internal/data/models"
	"gorm.io/gorm"
)

type OIDCRepository struct {
	DB *gorm.DB
}

func NewOIDCRepository(db *gorm.DB) *OIDCRepository {
	return &OIDCRepository{DB: db}
}

func (r *OIDCRepository) CreateConnection(ctx context.Context, conn *models.OIDCConnection) error {
	return r.DB.WithContext(ctx).Create(conn).Error
}

func (r *OIDCRepository) GetConnection(ctx context.Context, id string) (*models.OIDCConnection, error) {
	var conn models.OIDCConnection
	if err := r.DB.WithContext(ctx).First(&conn, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &conn, nil
}
