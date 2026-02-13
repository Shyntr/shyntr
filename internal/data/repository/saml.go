package repository

import (
	"context"
	"errors"
	"time"

	"github.com/nevzatcirak/shyntr/internal/data/models"
	"gorm.io/gorm"
)

type SAMLRepository struct {
	DB *gorm.DB
}

func NewSAMLRepository(db *gorm.DB) *SAMLRepository {
	return &SAMLRepository{DB: db}
}

func (r *SAMLRepository) CheckAndSaveMessageID(ctx context.Context, messageID, tenantID string, expiration time.Duration) error {
	go func() {
		r.DB.Where("expires_at < ?", time.Now()).Delete(&models.SAMLReplayCache{})
	}()

	var count int64
	if err := r.DB.WithContext(ctx).Model(&models.SAMLReplayCache{}).Where("message_id = ?", messageID).Count(&count).Error; err != nil {
		return err
	}

	if count > 0 {
		return errors.New("replay detected: message id already processed")
	}

	cacheEntry := models.SAMLReplayCache{
		MessageID: messageID,
		TenantID:  tenantID,
		ExpiresAt: time.Now().Add(expiration),
		CreatedAt: time.Now(),
	}

	if err := r.DB.WithContext(ctx).Create(&cacheEntry).Error; err != nil {
		return errors.New("replay detected: concurrent transaction")
	}

	return nil
}
func (r *SAMLRepository) CreateConnection(ctx context.Context, conn *models.SAMLConnection) error {
	return r.DB.WithContext(ctx).Create(conn).Error
}

func (r *SAMLRepository) GetConnection(ctx context.Context, id string) (*models.SAMLConnection, error) {
	var conn models.SAMLConnection
	err := r.DB.WithContext(ctx).First(&conn, "id = ?", id).Error
	return &conn, err
}

func (r *SAMLRepository) FindConnectionByEntityID(ctx context.Context, tenantID, entityID string) (*models.SAMLConnection, error) {
	var conn models.SAMLConnection
	err := r.DB.WithContext(ctx).Where("tenant_id = ? AND idp_entity_id = ?", tenantID, entityID).First(&conn).Error
	return &conn, err
}

func (r *SAMLRepository) ListConnections(ctx context.Context, tenantID string) ([]models.SAMLConnection, error) {
	var conns []models.SAMLConnection
	err := r.DB.WithContext(ctx).Where("tenant_id = ?", tenantID).Find(&conns).Error
	return conns, err
}

func (r *SAMLRepository) UpdateConnection(ctx context.Context, conn *models.SAMLConnection) error {
	return r.DB.WithContext(ctx).Save(conn).Error
}

func (r *SAMLRepository) DeleteConnection(ctx context.Context, id string) error {
	return r.DB.WithContext(ctx).Delete(&models.SAMLConnection{}, "id = ?", id).Error
}
