package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"

	"github.com/lib/pq"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
)

type SAMLClientGORM struct {
	ID                      string                                 `gorm:"primaryKey;type:varchar(255)"`
	TenantID                string                                 `gorm:"type:varchar(255);not null;index"`
	Name                    string                                 `gorm:"type:varchar(255);not null"`
	EntityID                string                                 `gorm:"type:varchar(255);not null"`
	ACSURL                  string                                 `gorm:"type:text;not null"`
	SLOURL                  string                                 `gorm:"type:text"`
	SPCertificate           string                                 `gorm:"type:text"`
	SPEncryptionCertificate string                                 `gorm:"type:text"`
	MetadataURL             string                                 `gorm:"type:text"`
	AttributeMapping        map[string]entity.AttributeMappingRule `gorm:"serializer:json"`
	AllowedScopes           pq.StringArray                         `gorm:"type:text[]"`
	ForceAuthn              bool                                   `gorm:"default:false"`
	SignResponse            bool                                   `gorm:"default:true"`
	SignAssertion           bool                                   `gorm:"default:true"`
	EncryptAssertion        bool                                   `gorm:"default:false"`
	Active                  bool                                   `gorm:"default:true;index"`
	CreatedAt               time.Time                              `gorm:"autoCreateTime"`
	UpdatedAt               time.Time                              `gorm:"autoUpdateTime"`
	DeletedAt               gorm.DeletedAt                         `gorm:"index"`
}

func (SAMLClientGORM) TableName() string { return "saml_clients" }

func (c *SAMLClientGORM) BeforeCreate(tx *gorm.DB) (err error) {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return
}

func (m *SAMLClientGORM) ToDomain() *entity.SAMLClient {
	return &entity.SAMLClient{
		ID:                      m.ID,
		TenantID:                m.TenantID,
		Name:                    m.Name,
		EntityID:                m.EntityID,
		ACSURL:                  m.ACSURL,
		SLOURL:                  m.SLOURL,
		SPCertificate:           m.SPCertificate,
		SPEncryptionCertificate: m.SPEncryptionCertificate,
		MetadataURL:             m.MetadataURL,
		AttributeMapping:        m.AttributeMapping,
		AllowedScopes:           m.AllowedScopes,
		ForceAuthn:              m.ForceAuthn,
		SignResponse:            m.SignResponse,
		SignAssertion:           m.SignAssertion,
		EncryptAssertion:        m.EncryptAssertion,
		Active:                  m.Active,
		CreatedAt:               m.CreatedAt,
		UpdatedAt:               m.UpdatedAt,
	}
}

func FromDomainSAMLClient(e *entity.SAMLClient) *SAMLClientGORM {
	return &SAMLClientGORM{
		ID:                      e.ID,
		TenantID:                e.TenantID,
		Name:                    e.Name,
		EntityID:                e.EntityID,
		ACSURL:                  e.ACSURL,
		SLOURL:                  e.SLOURL,
		SPCertificate:           e.SPCertificate,
		SPEncryptionCertificate: e.SPEncryptionCertificate,
		MetadataURL:             e.MetadataURL,
		AttributeMapping:        e.AttributeMapping,
		AllowedScopes:           e.AllowedScopes,
		ForceAuthn:              e.ForceAuthn,
		SignResponse:            e.SignResponse,
		SignAssertion:           e.SignAssertion,
		EncryptAssertion:        e.EncryptAssertion,
		Active:                  e.Active,
	}
}
