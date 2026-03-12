package repository

import (
	"context"
	"errors"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/entity"
	"gorm.io/gorm"
)

type webhookRepository struct {
	db *gorm.DB
}

func NewWebhookRepository(db *gorm.DB) port.WebhookRepository {
	return &webhookRepository{db: db}
}

func (r *webhookRepository) Create(ctx context.Context, webhook *entity.Webhook) error {
	dbModel := models.FromDomainWebhook(webhook)
	return r.db.WithContext(ctx).Create(dbModel).Error
}

func (r *webhookRepository) GetByID(ctx context.Context, id string) (*entity.Webhook, error) {
	var dbModel models.WebhookGORM
	if err := r.db.WithContext(ctx).First(&dbModel, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("webhook not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *webhookRepository) Update(ctx context.Context, webhook *entity.Webhook) error {
	dbModel := models.FromDomainWebhook(webhook)
	return r.db.WithContext(ctx).Model(&models.WebhookGORM{}).Where("id = ?", webhook.ID).Updates(dbModel).Error
}

func (r *webhookRepository) Delete(ctx context.Context, id string) error {
	result := r.db.WithContext(ctx).Where("id = ?", id).Delete(&models.WebhookGORM{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("webhook not found")
	}
	return nil
}

func (r *webhookRepository) List(ctx context.Context) ([]*entity.Webhook, error) {
	var dbModels []models.WebhookGORM
	if err := r.db.WithContext(ctx).Find(&dbModels).Error; err != nil {
		return nil, err
	}
	var entities []*entity.Webhook
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}

func (r *webhookRepository) ListByEvent(ctx context.Context, event string) ([]*entity.Webhook, error) {
	var dbModels []models.WebhookGORM
	// Veritabanı bağımsız (Postgres JSONB / MySQL JSON) arama için LIKE kullanılıyor
	// (Gelişmiş DB operasyonlarında PostgreSQL spesifik jsonb ops. kullanılabilir)
	query := "%\"" + event + "\"%"
	if err := r.db.WithContext(ctx).Where("is_active = ? AND events LIKE ?", true, query).Find(&dbModels).Error; err != nil {
		return nil, err
	}
	var entities []*entity.Webhook
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}
