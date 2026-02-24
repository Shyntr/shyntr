package models

import (
	"time"

	"github.com/lib/pq"
	"gorm.io/gorm"
)

// OAuth2Session stores the session data for OAuth2 tokens.
type OAuth2Session struct {
	Signature       string         `gorm:"primaryKey;type:varchar(255)"` // The token signature
	Type            string         `gorm:"primaryKey;type:varchar(50)"`  // access_token, refresh_token, authorize_code, pkce, oidc
	RequestID       string         `gorm:"index;not null"`
	ClientID        string         `gorm:"index;not null"`
	Subject         string         `gorm:"index"`
	TokenFamilyID   string         `gorm:"type:text;index"`
	Active          bool           `gorm:"default:true"`
	GrantedScopes   pq.StringArray `gorm:"type:text[]"`
	RequestData     []byte         `gorm:"type:jsonb"`
	SessionData     []byte         `gorm:"type:jsonb"`
	ExpiresAt       time.Time      `gorm:"index"`
	GraceExpiresAt  *time.Time     `gorm:"index"`
	GraceUsedAt     *time.Time     `gorm:"index"`
	ReuseDetectedAt *time.Time     `gorm:"index"`
	UsedAt          *time.Time     `gorm:"index"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       gorm.DeletedAt `gorm:"index"`
}
