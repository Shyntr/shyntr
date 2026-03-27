package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

type WebhookRepository interface {
	Create(ctx context.Context, webhook *model.Webhook) error
	GetByID(ctx context.Context, id string) (*model.Webhook, error)
	Update(ctx context.Context, webhook *model.Webhook) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]*model.Webhook, error)
	ListByEvent(ctx context.Context, event string) ([]*model.Webhook, error)
}

type WebhookEventRepository interface {
	SaveEvent(ctx context.Context, event *model.WebhookEvent) error
	GetPendingEvents(ctx context.Context, webhookID string, limit int) ([]*model.WebhookEvent, error)
	DeleteEvent(ctx context.Context, eventID string) error
	IncrementFailure(ctx context.Context, webhookID string) (int, error)
	ResetFailureAndActivate(ctx context.Context, webhookID string) error
	DeactivateWebhook(ctx context.Context, webhookID string) error
}
