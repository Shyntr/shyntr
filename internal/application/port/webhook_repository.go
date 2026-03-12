package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/entity"
)

type WebhookRepository interface {
	Create(ctx context.Context, webhook *entity.Webhook) error
	GetByID(ctx context.Context, id string) (*entity.Webhook, error)
	Update(ctx context.Context, webhook *entity.Webhook) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]*entity.Webhook, error)
	ListByEvent(ctx context.Context, event string) ([]*entity.Webhook, error)
}

type WebhookEventRepository interface {
	SaveEvent(ctx context.Context, event *entity.WebhookEvent) error
	GetPendingEvents(ctx context.Context, webhookID string, limit int) ([]*entity.WebhookEvent, error)
	DeleteEvent(ctx context.Context, eventID string) error
	IncrementFailure(ctx context.Context, webhookID string) (int, error)
	ResetFailureAndActivate(ctx context.Context, webhookID string) error
	DeactivateWebhook(ctx context.Context, webhookID string) error
}
