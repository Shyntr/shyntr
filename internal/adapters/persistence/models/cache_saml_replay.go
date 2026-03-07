package models

import "time"

type SAMLReplayCache struct {
	MessageID string    `gorm:"primaryKey"`
	TenantID  string    `gorm:"index"`
	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time `gorm:"autoCreateTime;index"`
}
