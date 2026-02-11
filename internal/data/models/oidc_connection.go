package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// OIDCConnection represents a trust relationship with an external OIDC Provider.
// Shyntr acts as an OIDC Client (RP) in this relationship.
type OIDCConnection struct {
	ID       string `gorm:"primaryKey"`
	TenantID string `gorm:"index;not null"`
	Name     string `gorm:"not null"`

	IssuerURL    string `gorm:"not null"`
	ClientID     string `gorm:"not null"`
	ClientSecret string `gorm:"not null"`

	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	JWKSURI               string

	Scopes pq.StringArray `gorm:"type:text[]"` // ["openid", "profile", "email"]

	AttributeMapping []byte `gorm:"type:jsonb"`

	Active    bool `gorm:"default:true"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (c *OIDCConnection) BeforeCreate(tx *gorm.DB) (err error) {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return
}
