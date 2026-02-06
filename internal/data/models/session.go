package models

import (
	"gorm.io/gorm"
	"time"
)

// OAuth2Session stores the serialized session data for Access/Refresh tokens.
type OAuth2Session struct {
	Signature   string    `gorm:"primaryKey"`
	RequestID   string    `gorm:"index;not null"`
	ClientID    string    `gorm:"index;not null"`
	Subject     string    `gorm:"index"`
	Type        string    `gorm:"index;not null"` // e.g., access_token, refresh_token
	Active      bool      `gorm:"default:true"`
	SessionData []byte    `gorm:"type:jsonb"` // Stores the JSON payload
	ExpiresAt   time.Time `gorm:"index"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}
