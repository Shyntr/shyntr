package models

import (
	"time"

	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type OIDCConnectionGORM struct {
	ID                    string                                `gorm:"primaryKey;type:varchar(255)"`
	TenantID              string                                `gorm:"type:varchar(255);not null;index"`
	Name                  string                                `gorm:"type:varchar(255);not null"`
	IssuerURL             string                                `gorm:"type:varchar(255);not null"`
	ClientID              string                                `gorm:"type:varchar(255);not null"`
	ClientSecret          string                                `gorm:"type:varchar(255)"`
	AuthorizationEndpoint string                                `gorm:"type:varchar(255)"`
	TokenEndpoint         string                                `gorm:"type:varchar(255)"`
	UserInfoEndpoint      string                                `gorm:"type:varchar(255)"`
	JWKSURI               string                                `gorm:"type:varchar(255)"`
	EndSessionEndpoint    string                                `gorm:"type:varchar(255)"`
	Scopes                pq.StringArray                        `gorm:"type:text[]"`
	AttributeMapping      map[string]model.AttributeMappingRule `gorm:"serializer:json"`
	Active                bool                                  `gorm:"default:true"`
	CreatedAt             time.Time                             `gorm:"autoCreateTime"`
	UpdatedAt             time.Time                             `gorm:"autoUpdateTime"`
	DeletedAt             gorm.DeletedAt                        `gorm:"index"`
}

func (OIDCConnectionGORM) TableName() string { return "oidc_connections" }

func (c *OIDCConnectionGORM) BeforeCreate(tx *gorm.DB) (err error) {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return
}
func (m *OIDCConnectionGORM) ToDomain() *model.OIDCConnection {
	return &model.OIDCConnection{
		ID:                    m.ID,
		TenantID:              m.TenantID,
		Name:                  m.Name,
		IssuerURL:             m.IssuerURL,
		ClientID:              m.ClientID,
		ClientSecret:          m.ClientSecret,
		AuthorizationEndpoint: m.AuthorizationEndpoint,
		TokenEndpoint:         m.TokenEndpoint,
		UserInfoEndpoint:      m.UserInfoEndpoint,
		JWKSURI:               m.JWKSURI,
		EndSessionEndpoint:    m.EndSessionEndpoint,
		Scopes:                m.Scopes,
		AttributeMapping:      m.AttributeMapping,
		Active:                m.Active,
		CreatedAt:             m.CreatedAt,
		UpdatedAt:             m.UpdatedAt,
	}
}

func FromDomainOIDCConnection(e *model.OIDCConnection) *OIDCConnectionGORM {
	return &OIDCConnectionGORM{
		ID:                    e.ID,
		TenantID:              e.TenantID,
		Name:                  e.Name,
		IssuerURL:             e.IssuerURL,
		ClientID:              e.ClientID,
		ClientSecret:          e.ClientSecret,
		AuthorizationEndpoint: e.AuthorizationEndpoint,
		TokenEndpoint:         e.TokenEndpoint,
		UserInfoEndpoint:      e.UserInfoEndpoint,
		JWKSURI:               e.JWKSURI,
		EndSessionEndpoint:    e.EndSessionEndpoint,
		Scopes:                e.Scopes,
		AttributeMapping:      e.AttributeMapping,
		Active:                e.Active,
	}
}
