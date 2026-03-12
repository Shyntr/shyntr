package models

import (
	"time"

	"github.com/Shyntr/shyntr/internal/domain/entity"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type SAMLConnectionGORM struct {
	ID                       string                                 `gorm:"primaryKey;type:varchar(255)"`
	TenantID                 string                                 `gorm:"type:varchar(255);not null;index"`
	Name                     string                                 `gorm:"type:varchar(255);not null"`
	IdpMetadataXML           string                                 `gorm:"type:text"`
	IdpEntityID              string                                 `gorm:"type:varchar(255)"`
	IdpSingleSignOn          string                                 `gorm:"type:text"`
	IdpSloUrl                string                                 `gorm:"type:text"`
	MetadataURL              string                                 `gorm:"type:text"`
	IdpCertificate           string                                 `gorm:"type:text"`
	IdpEncryptionCertificate string                                 `gorm:"type:text"`
	SPPrivateKey             string                                 `gorm:"type:text"`
	AttributeMapping         map[string]entity.AttributeMappingRule `gorm:"serializer:json"`
	ForceAuthn               bool                                   `gorm:"default:false"`
	SignRequest              bool                                   `gorm:"default:false"`
	Active                   bool                                   `gorm:"default:true"`
	SPCertificate            string                                 `gorm:"type:text"`
	RequestedContexts        pq.StringArray                         `gorm:"type:text[]" `
	CreatedAt                time.Time                              `gorm:"autoCreateTime"`
	UpdatedAt                time.Time                              `gorm:"autoUpdateTime"`
	DeletedAt                gorm.DeletedAt                         `gorm:"index"`
}

func (SAMLConnectionGORM) TableName() string { return "saml_connections" }

func (c *SAMLConnectionGORM) BeforeCreate(tx *gorm.DB) (err error) {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return
}

func (m *SAMLConnectionGORM) ToDomain() *entity.SAMLConnection {
	return &entity.SAMLConnection{
		ID:                       m.ID,
		TenantID:                 m.TenantID,
		Name:                     m.Name,
		IdpMetadataXML:           m.IdpMetadataXML,
		IdpEntityID:              m.IdpEntityID,
		IdpSingleSignOn:          m.IdpSingleSignOn,
		IdpSloUrl:                m.IdpSloUrl,
		MetadataURL:              m.MetadataURL,
		IdpCertificate:           m.IdpCertificate,
		IdpEncryptionCertificate: m.IdpEncryptionCertificate,
		SPPrivateKey:             m.SPPrivateKey,
		AttributeMapping:         m.AttributeMapping,
		ForceAuthn:               m.ForceAuthn,
		SignRequest:              m.SignRequest,
		Active:                   m.Active,
		SPCertificate:            m.SPCertificate,
		RequestedContexts:        m.RequestedContexts,
		CreatedAt:                m.CreatedAt,
		UpdatedAt:                m.UpdatedAt,
	}
}

func FromDomainSAMLConnection(e *entity.SAMLConnection) *SAMLConnectionGORM {
	return &SAMLConnectionGORM{
		ID:                       e.ID,
		TenantID:                 e.TenantID,
		Name:                     e.Name,
		IdpMetadataXML:           e.IdpMetadataXML,
		IdpEntityID:              e.IdpEntityID,
		IdpSingleSignOn:          e.IdpSingleSignOn,
		IdpSloUrl:                e.IdpSloUrl,
		MetadataURL:              e.MetadataURL,
		IdpCertificate:           e.IdpCertificate,
		IdpEncryptionCertificate: e.IdpEncryptionCertificate,
		SPPrivateKey:             e.SPPrivateKey,
		AttributeMapping:         e.AttributeMapping,
		ForceAuthn:               e.ForceAuthn,
		SignRequest:              e.SignRequest,
		Active:                   e.Active,
		SPCertificate:            e.SPCertificate,
		RequestedContexts:        e.RequestedContexts,
	}
}
