package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SAMLConnection represents a trust relationship with an external SAML Identity Provider.
type SAMLConnection struct {
	ID       string `gorm:"primaryKey"`
	TenantID string `gorm:"index;not null"`
	Name     string `gorm:"not null"`

	IdpMetadataURL string `gorm:"type:text"`
	IdpMetadataXML string `gorm:"type:text"`
	IdpEntityID    string `gorm:"index"`

	SPCertificate string `gorm:"type:text"`
	SPPrivateKey  string `gorm:"type:text"`

	AllowUnencrypted bool `gorm:"default:false"` // False ise, şifresiz assertion'ları reddeder (Prod için False olmalı)
	ForceAuthn       bool `gorm:"default:false"` // True ise, kullanıcı IDP'de oturum açmış olsa bile tekrar şifre sorulur.

	// Attribute Mapping: {"sub": "uid", "email": "mail"}
	AttributeMapping []byte `gorm:"type:jsonb"`

	Active    bool `gorm:"default:true"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (s *SAMLConnection) BeforeCreate(tx *gorm.DB) (err error) {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return
}
