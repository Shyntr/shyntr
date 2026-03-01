package models

import (
	"time"
)

type Webhook struct {
	ID           string    `json:"id" gorm:"primaryKey;type:varchar(50)"`
	Name         string    `json:"name" gorm:"type:varchar(100)"`
	URL          string    `json:"url" gorm:"type:varchar(255)"`
	Secret       string    `json:"secret" gorm:"type:varchar(255)"`   // HMAC signature
	TenantIDs    []string  `json:"tenant_ids" gorm:"serializer:json"` // e.g. : ["tenant-1", "^acme-.*$", "*"]
	Events       []string  `json:"events" gorm:"serializer:json"`     // e.g. : ["user.login.ext", "^user\\..*"]
	IsActive     bool      `json:"is_active" gorm:"default:true"`
	FailureCount int       `json:"failure_count" gorm:"default:0"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type WebhookEvent struct {
	ID        string    `gorm:"primaryKey;type:varchar(50)"`
	WebhookID string    `gorm:"index;not null"`
	TenantID  string    `gorm:"index"`
	EventType string    `gorm:"index"`
	Payload   []byte    `gorm:"type:jsonb"`
	CreatedAt time.Time `gorm:"index"`
}
