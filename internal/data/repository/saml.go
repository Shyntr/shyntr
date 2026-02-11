package repository

import (
	"context"

	"github.com/nevzatcirak/shyntr/internal/data/models"
	"gorm.io/gorm"
)

type SAMLRepository struct {
	DB *gorm.DB
}

func NewSAMLRepository(db *gorm.DB) *SAMLRepository {
	return &SAMLRepository{DB: db}
}

func (r *SAMLRepository) CreateConnection(ctx context.Context, conn *models.SAMLConnection) error {
	return r.DB.WithContext(ctx).Create(conn).Error
}

func (r *SAMLRepository) GetConnection(ctx context.Context, id string) (*models.SAMLConnection, error) {
	var conn models.SAMLConnection
	if err := r.DB.WithContext(ctx).First(&conn, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &conn, nil
}

func (r *SAMLRepository) GetConnectionsByTenant(ctx context.Context, tenantID string) ([]models.SAMLConnection, error) {
	var conns []models.SAMLConnection
	if err := r.DB.WithContext(ctx).Where("tenant_id = ?", tenantID).Find(&conns).Error; err != nil {
		return nil, err
	}
	return conns, nil
}

func (r *SAMLRepository) FindConnectionByEntityID(ctx context.Context, tenantID, entityID string) (*models.SAMLConnection, error) {
	var conn models.SAMLConnection
	if err := r.DB.WithContext(ctx).Where("tenant_id = ? AND idp_entity_id = ?", tenantID, entityID).First(&conn).Error; err != nil {
		return nil, err
	}
	return &conn, nil
}

func (r *SAMLRepository) UpdateConnection(ctx context.Context, conn *models.SAMLConnection) error {
	return r.DB.WithContext(ctx).Save(conn).Error
}

func (r *SAMLRepository) DeleteConnection(ctx context.Context, id string) error {
	return r.DB.WithContext(ctx).Delete(&models.SAMLConnection{}, "id = ?", id).Error
}
