package models

import (
	"time"
)

// SAMLConnection stores configuration for external SAML Identity Providers.
type SAMLConnection struct {
	ID             string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Tenant         string `gorm:"index;not null"`
	IdpSSOURL      string `gorm:"not null"`
	IdpEntityID    string `gorm:"not null"`
	IdpCert        string `gorm:"type:text"`
	RelyingPartyID string
	Active         bool `gorm:"default:true"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
