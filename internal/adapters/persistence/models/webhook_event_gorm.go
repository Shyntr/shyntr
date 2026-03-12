package models

import (
	"time"

	"github.com/nevzatcirak/shyntr/internal/domain/entity"
)

type WebhookEventGORM struct {
	ID        string    `gorm:"primaryKey;type:varchar(255)"`
	WebhookID string    `gorm:"type:varchar(255);not null;index"`
	TenantID  string    `gorm:"type:varchar(255);not null;index"`
	EventType string    `gorm:"type:varchar(255);not null"`
	Payload   []byte    `gorm:"type:jsonb;not null"`
	CreatedAt time.Time `gorm:"autoCreateTime;index"`
}

func (WebhookEventGORM) TableName() string { return "webhook_events" }

func (m *WebhookEventGORM) ToDomain() *entity.WebhookEvent {
	return &entity.WebhookEvent{
		ID:        m.ID,
		WebhookID: m.WebhookID,
		TenantID:  m.TenantID,
		EventType: m.EventType,
		Payload:   m.Payload,
		CreatedAt: m.CreatedAt,
	}
}

func FromDomainWebhookEvent(e *entity.WebhookEvent) *WebhookEventGORM {
	return &WebhookEventGORM{
		ID:        e.ID,
		WebhookID: e.WebhookID,
		TenantID:  e.TenantID,
		EventType: e.EventType,
		Payload:   e.Payload,
		CreatedAt: e.CreatedAt,
	}
}
