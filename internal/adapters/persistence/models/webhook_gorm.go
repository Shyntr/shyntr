package models

import (
	"time"

	"github.com/lib/pq"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
	"gorm.io/gorm"
)

type WebhookGORM struct {
	ID           string         `gorm:"primaryKey;type:varchar(255)"`
	Name         string         `gorm:"type:varchar(255);not null"`
	URL          string         `gorm:"type:text;not null"`
	Secret       string         `gorm:"type:varchar(255)"`
	TenantIDs    pq.StringArray `gorm:"type:text[]"`
	Events       pq.StringArray `gorm:"type:text[]"`
	IsActive     bool           `gorm:"default:true"`
	FailureCount int            `gorm:"default:0"`
	CreatedAt    time.Time      `gorm:"autoCreateTime"`
	UpdatedAt    time.Time      `gorm:"autoUpdateTime"`
	DeletedAt    gorm.DeletedAt `gorm:"index"`
}

func (WebhookGORM) TableName() string { return "webhooks" }

func (m *WebhookGORM) ToDomain() *entity.Webhook {
	return &entity.Webhook{
		ID:           m.ID,
		Name:         m.Name,
		URL:          m.URL,
		Secret:       m.Secret,
		TenantIDs:    m.TenantIDs,
		Events:       m.Events,
		IsActive:     m.IsActive,
		FailureCount: m.FailureCount,
		CreatedAt:    m.CreatedAt,
		UpdatedAt:    m.UpdatedAt,
	}
}

func FromDomainWebhook(e *entity.Webhook) *WebhookGORM {
	return &WebhookGORM{
		ID:           e.ID,
		Name:         e.Name,
		URL:          e.URL,
		Secret:       e.Secret,
		TenantIDs:    e.TenantIDs,
		Events:       e.Events,
		IsActive:     e.IsActive,
		FailureCount: e.FailureCount,
	}
}
