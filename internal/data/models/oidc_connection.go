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
	ID       string `gorm:"primaryKey" json:"id"`
	TenantID string `gorm:"index;not null" json:"tenant_id"`
	Name     string `gorm:"not null" json:"name"`

	IssuerURL    string `gorm:"not null" json:"issuer_url"`
	ClientID     string `gorm:"not null" json:"client_id"`
	ClientSecret string `gorm:"not null" json:"client_secret"`

	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"user_info_endpoint"`
	JWKSURI               string `json:"jwks_uri"`

	Scopes pq.StringArray `gorm:"type:text[]" json:"scopes"`

	AttributeMapping []byte `gorm:"type:jsonb" json:"attribute_mapping"`

	Active    bool           `gorm:"default:true" json:"active"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (c *OIDCConnection) BeforeCreate(tx *gorm.DB) (err error) {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return
}
