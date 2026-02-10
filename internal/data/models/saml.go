package models

import (
	"time"

	"github.com/google/uuid" // Eklendi
	"gorm.io/gorm"
)

// SAMLConnection stores configuration for external SAML Identity Providers.
type SAMLConnection struct {
	ID             string `gorm:"primaryKey"`
	Tenant         string `gorm:"index;not null"`
	IdpSSOURL      string `gorm:"not null"`
	IdpEntityID    string `gorm:"not null"`
	IdpCert        string `gorm:"type:text"`
	RelyingPartyID string
	Active         bool `gorm:"default:true"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (s *SAMLConnection) BeforeCreate(tx *gorm.DB) (err error) {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return
}
