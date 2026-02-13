package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type SAMLConnection struct {
	ID                string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	TenantID          string `gorm:"index;not null"`
	Name              string `gorm:"not null"`
	IdpMetadataXML    string `gorm:"type:text"`
	IdpEntityID       string `gorm:"index"`
	IdpSingleSignOn   string
	AttributeMapping  []byte         `gorm:"type:jsonb"`
	ForceAuthn        bool           `gorm:"default:false"`
	SPPrivateKey      string         `gorm:"type:text"`
	SPCertificate     string         `gorm:"type:text"`
	SignRequest       bool           `gorm:"default:true"`
	Active            bool           `gorm:"default:true"`
	RequestedContexts pq.StringArray `gorm:"type:text[]"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (c *SAMLConnection) BeforeCreate(tx *gorm.DB) (err error) {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return
}

type SAMLClient struct {
	ID               string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	TenantID         string `gorm:"index;not null"`
	Name             string `gorm:"not null"`
	EntityID         string `gorm:"uniqueIndex;not null"`
	ACSURL           string `gorm:"not null"`
	SPCertificate    string `gorm:"type:text"`
	AttributeMapping []byte `gorm:"type:jsonb"`

	ForceAuthn       bool `gorm:"default:false"`
	SignResponse     bool `gorm:"default:true"`
	SignAssertion    bool `gorm:"default:true"`
	EncryptAssertion bool `gorm:"default:false"`

	Active    bool `gorm:"default:true"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (c *SAMLClient) BeforeCreate(tx *gorm.DB) (err error) {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return
}

type SAMLReplayCache struct {
	MessageID string    `gorm:"primaryKey"`
	TenantID  string    `gorm:"index"`
	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time
}
