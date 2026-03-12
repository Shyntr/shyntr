package repository

import (
	"context"
	"errors"
	"time"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"gorm.io/gorm"
)

type samlReplayRepository struct {
	db *gorm.DB
}

func NewSAMLReplayRepository(db *gorm.DB) port.SAMLReplayRepository {
	return &samlReplayRepository{db: db}
}

func (r *samlReplayRepository) CheckAndSaveMessageID(ctx context.Context, messageID, tenantID string, expiration time.Duration) error {
	go func() {
		r.db.Where("expires_at < ?", time.Now()).Delete(&models.SAMLReplayCache{})
	}()

	var count int64
	if err := r.db.WithContext(ctx).Model(&models.SAMLReplayCache{}).Where("message_id = ?", messageID).Count(&count).Error; err != nil {
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

	if err := r.db.WithContext(ctx).Create(&cacheEntry).Error; err != nil {
		return errors.New("replay detected: concurrent transaction")
	}

	return nil
}
