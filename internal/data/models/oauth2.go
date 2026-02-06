package models

import (
	"github.com/lib/pq"
	"time"
)

// OAuth2Client represents a registered application.
// Now supports Multi-Tenancy via TenantID and AppID.
type OAuth2Client struct {
	ID            string         `gorm:"primaryKey"`
	TenantID      string         `gorm:"index;not null"` // "google", "my-saas-customer-1", etc.
	AppID         string         `gorm:"index"`          // Optional logical grouping
	Secret        string         `gorm:"not null"`
	RedirectURIs  pq.StringArray `gorm:"type:text[]"`
	GrantTypes    pq.StringArray `gorm:"type:text[]"`
	ResponseTypes pq.StringArray `gorm:"type:text[]"`
	Scopes        pq.StringArray `gorm:"type:text[]"`
	Public        bool
	SkipConsent   bool `gorm:"default:false"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
