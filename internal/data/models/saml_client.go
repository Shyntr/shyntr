package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type SAMLClient struct {
	ID       string `gorm:"primaryKey"`
	TenantID string `gorm:"index;not null"`
	Name     string `gorm:"not null"`

	EntityID string `gorm:"index;not null"`

	ACSURL string `gorm:"not null"`

	SPCertificate string `gorm:"type:text"`

	ForceAuthn       bool `gorm:"default:false"`
	SignResponse     bool `gorm:"default:true"`
	SignAssertion    bool `gorm:"default:true"`
	EncryptAssertion bool `gorm:"default:false"`

	AttributeMapping []byte `gorm:"type:jsonb"`

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
