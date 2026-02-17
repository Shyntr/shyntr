package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type SAMLConnection struct {
	ID       string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()" json:"id"`
	TenantID string `gorm:"index;not null" json:"tenant_id"`
	Name     string `gorm:"not null" json:"name"`

	IdpMetadataXML  string `gorm:"type:text" json:"idp_metadata_xml"`
	IdpEntityID     string `gorm:"index" json:"idp_entity_id"`
	IdpSingleSignOn string `json:"idp_single_sign_on"`

	AttributeMapping map[string]string `gorm:"serializer:json" json:"attribute_mapping"`

	ForceAuthn  bool `gorm:"default:false" json:"force_authn"`
	SignRequest bool `gorm:"default:true" json:"sign_request"`

	SPPrivateKey  string `gorm:"type:text" json:"sp_private_key"`
	SPCertificate string `gorm:"type:text" json:"sp_certificate"`

	Active            bool           `gorm:"default:true" json:"active"`
	RequestedContexts pq.StringArray `gorm:"type:text[]" json:"requested_contexts"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (c *SAMLConnection) BeforeCreate(tx *gorm.DB) (err error) {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return
}

type SAMLClient struct {
	ID               string            `gorm:"primaryKey;type:uuid;default:gen_random_uuid()" json:"id"`
	TenantID         string            `gorm:"index;not null" json:"tenant_id"`
	Name             string            `gorm:"not null" json:"name"`
	EntityID         string            `gorm:"uniqueIndex;not null" json:"entity_id"`
	ACSURL           string            `gorm:"not null" json:"acs_url"`
	SPCertificate    string            `gorm:"type:text" json:"sp_certificate"`
	AttributeMapping map[string]string `gorm:"serializer:json" json:"attribute_mapping"`

	ForceAuthn       bool `gorm:"default:false" json:"force_authn"`
	SignResponse     bool `gorm:"default:true" json:"sign_response"`
	SignAssertion    bool `gorm:"default:true" json:"sign_assertion"`
	EncryptAssertion bool `gorm:"default:false" json:"encrypt_assertion"`

	Active    bool           `gorm:"default:true" json:"active"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (c *SAMLClient) BeforeCreate(tx *gorm.DB) (err error) {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return
}

type SAMLReplayCache struct {
	MessageID string    `gorm:"primaryKey" json:"message_id"`
	TenantID  string    `gorm:"index" json:"tenant_id"`
	ExpiresAt time.Time `gorm:"index" json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}
