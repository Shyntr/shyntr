package models

import (
	"time"

	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// LDAPConnectionGORM persists LDAP/AD identity-provider connections.
// BindPasswordEncrypted stores the AES-256-GCM ciphertext of the service-account
// password (same pattern as CryptoKeyGORM.KeyData). Decryption is the
// responsibility of ldapConnectionRepository, never of this struct.
type LDAPConnectionGORM struct {
	ID                    string                                `gorm:"primaryKey;type:varchar(255)"`
	TenantID              string                                `gorm:"type:varchar(255);not null;index"`
	Name                  string                                `gorm:"type:varchar(255);not null"`
	ServerURL             string                                `gorm:"type:varchar(512);not null"`
	BindDN                string                                `gorm:"type:varchar(512)"`
	BindPasswordEncrypted []byte                                `gorm:"type:bytea"` // AES-256-GCM encrypted, base64 stored as bytes
	BaseDN                string                                `gorm:"type:varchar(512);not null"`
	UserSearchFilter      string                                `gorm:"type:varchar(512)"`
	UserSearchAttributes  pq.StringArray                        `gorm:"type:text[]"`
	GroupSearchFilter     string                                `gorm:"type:varchar(512)"`
	GroupSearchBaseDN     string                                `gorm:"type:varchar(512)"`
	AttributeMapping      map[string]model.AttributeMappingRule `gorm:"serializer:json"`
	StartTLS              bool                                  `gorm:"default:false"`
	TLSInsecureSkipVerify bool                                  `gorm:"default:false"`
	Active                bool                                  `gorm:"default:true"`
	CreatedAt             time.Time                             `gorm:"autoCreateTime"`
	UpdatedAt             time.Time                             `gorm:"autoUpdateTime"`
	DeletedAt             gorm.DeletedAt                        `gorm:"index"`
}

func (LDAPConnectionGORM) TableName() string { return "ldap_connections" }

func (c *LDAPConnectionGORM) BeforeCreate(tx *gorm.DB) (err error) {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return
}

// ToDomain converts this GORM model to a domain model.
// BindPassword is left empty; the repository layer decrypts BindPasswordEncrypted
// and populates it after calling this method.
func (m *LDAPConnectionGORM) ToDomain() *model.LDAPConnection {
	return &model.LDAPConnection{
		ID:                    m.ID,
		TenantID:              m.TenantID,
		Name:                  m.Name,
		ServerURL:             m.ServerURL,
		BindDN:                m.BindDN,
		BaseDN:                m.BaseDN,
		UserSearchFilter:      m.UserSearchFilter,
		UserSearchAttributes:  m.UserSearchAttributes,
		GroupSearchFilter:     m.GroupSearchFilter,
		GroupSearchBaseDN:     m.GroupSearchBaseDN,
		AttributeMapping:      m.AttributeMapping,
		StartTLS:              m.StartTLS,
		TLSInsecureSkipVerify: m.TLSInsecureSkipVerify,
		Active:                m.Active,
		CreatedAt:             m.CreatedAt,
		UpdatedAt:             m.UpdatedAt,
	}
}

// FromDomainLDAPConnection converts a domain model to a GORM model.
// BindPasswordEncrypted must be set by the repository after calling this function;
// it is intentionally left nil here to prevent accidental plaintext storage.
func FromDomainLDAPConnection(e *model.LDAPConnection) *LDAPConnectionGORM {
	return &LDAPConnectionGORM{
		ID:                    e.ID,
		TenantID:              e.TenantID,
		Name:                  e.Name,
		ServerURL:             e.ServerURL,
		BindDN:                e.BindDN,
		BaseDN:                e.BaseDN,
		UserSearchFilter:      e.UserSearchFilter,
		UserSearchAttributes:  e.UserSearchAttributes,
		GroupSearchFilter:     e.GroupSearchFilter,
		GroupSearchBaseDN:     e.GroupSearchBaseDN,
		AttributeMapping:      e.AttributeMapping,
		StartTLS:              e.StartTLS,
		TLSInsecureSkipVerify: e.TLSInsecureSkipVerify,
		Active:                e.Active,
	}
}
