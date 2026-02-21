package models

import (
	"time"

	"github.com/lib/pq"
	"gorm.io/gorm"
)

// OAuth2Session stores the session data for OAuth2 tokens.
// Fosite serializes the session into JSON/Properties, we store it here.
type OAuth2Session struct {
	Signature     string         `gorm:"primaryKey"` // The token signature
	RequestID     string         `gorm:"index;not null"`
	ClientID      string         `gorm:"index;not null"`
	Subject       string         `gorm:"index"`          // User ID (sub)
	Type          string         `gorm:"index;not null"` // access_token, refresh_token, authorize_code, pkce
	Active        bool           `gorm:"default:true"`
	GrantedScopes pq.StringArray `gorm:"type:text[]"`
	SessionData   []byte         `gorm:"type:jsonb"` // Serialized fosite session
	ExpiresAt     time.Time      `gorm:"index"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     gorm.DeletedAt `gorm:"index"`
}
