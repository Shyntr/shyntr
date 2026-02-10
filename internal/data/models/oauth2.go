package models

import (
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/lib/pq"
)

// OAuth2Client represents a registered application.
// Now supports Multi-Tenancy via TenantID and AppID.
type OAuth2Client struct {
	ID            string         `gorm:"primaryKey"`
	TenantID      string         `gorm:"index;not null"`
	AppID         string         `gorm:"index"`
	Secret        string         `gorm:"not null"`
	RedirectURIs  pq.StringArray `gorm:"type:text[]"`
	GrantTypes    pq.StringArray `gorm:"type:text[]"`
	ResponseTypes pq.StringArray `gorm:"type:text[]"`
	Scopes        pq.StringArray `gorm:"type:text[]"`

	PostLogoutRedirectURIs pq.StringArray `gorm:"type:text[]"`

	JSONWebKeys *jose.JSONWebKeySet `gorm:"type:jsonb"`

	Public      bool
	SkipConsent bool `gorm:"default:false"`

	AccessTokenLifespan  string `gorm:"default:''"`
	RefreshTokenLifespan string `gorm:"default:''"`
	IDTokenLifespan      string `gorm:"default:''"`

	CreatedAt time.Time
	UpdatedAt time.Time
}
