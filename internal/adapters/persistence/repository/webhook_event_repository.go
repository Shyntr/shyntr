package repository

import (
	"context"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/entity"
	"gorm.io/gorm"
)

type webhookEventRepository struct {
	db *gorm.DB
}

func NewWebhookEventRepository(db *gorm.DB) port.WebhookEventRepository {
	return &webhookEventRepository{db: db}
}

func (r *webhookEventRepository) SaveEvent(ctx context.Context, event *entity.WebhookEvent) error {
	dbModel := models.FromDomainWebhookEvent(event)
	return r.db.WithContext(ctx).Create(dbModel).Error
}

func (r *webhookEventRepository) GetPendingEvents(ctx context.Context, webhookID string, limit int) ([]*entity.WebhookEvent, error) {
	var dbModels []models.WebhookEventGORM
	if err := r.db.WithContext(ctx).
		Where("webhook_id = ?", webhookID).
		Order("created_at asc").
		Limit(limit).
		Find(&dbModels).Error; err != nil {
		return nil, err
	}

	var entities []*entity.WebhookEvent
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}

func (r *webhookEventRepository) DeleteEvent(ctx context.Context, eventID string) error {
	return r.db.WithContext(ctx).Where("id = ?", eventID).Delete(&models.WebhookEventGORM{}).Error
}

func (r *webhookEventRepository) IncrementFailure(ctx context.Context, webhookID string) (int, error) {
	var wh models.WebhookGORM
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&wh, "id = ?", webhookID).Error; err != nil {
			return err
		}
		wh.FailureCount += 1
		return tx.Save(&wh).Error
	})
	return wh.FailureCount, err
}

func (r *webhookEventRepository) ResetFailureAndActivate(ctx context.Context, webhookID string) error {
	return r.db.WithContext(ctx).Model(&models.WebhookGORM{}).
		Where("id = ?", webhookID).
		Updates(map[string]interface{}{"failures": 0, "is_active": true}).Error
}

func (r *webhookEventRepository) DeactivateWebhook(ctx context.Context, webhookID string) error {
	return r.db.WithContext(ctx).Model(&models.WebhookGORM{}).
		Where("id = ?", webhookID).
		Updates(map[string]interface{}{"is_active": false}).Error
}
