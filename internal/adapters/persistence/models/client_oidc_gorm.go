package models

import (
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/lib/pq"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
)

type OAuth2ClientGORM struct {
	ID                      string              `gorm:"primaryKey;type:varchar(255)"`
	TenantID                string              `gorm:"type:varchar(255);not null;index"`
	Name                    string              `gorm:"type:varchar(255);not null;default:'Unnamed Client'"`
	AppID                   string              `gorm:"index;type:varchar(255)"`
	Secret                  string              `gorm:"type:varchar(255)"`
	RedirectURIs            pq.StringArray      `gorm:"type:text[]"`
	GrantTypes              pq.StringArray      `gorm:"type:text[]"`
	ResponseTypes           pq.StringArray      `gorm:"type:text[]"`
	ResponseModes           pq.StringArray      `gorm:"type:text[]"`
	Scopes                  pq.StringArray      `gorm:"type:text[]"`
	Audience                pq.StringArray      `gorm:"type:text[]"`
	Public                  bool                `gorm:"default:false"`
	TokenEndpointAuthMethod string              `gorm:"type:varchar(50);default:'client_secret_basic'"`
	EnforcePKCE             bool                `gorm:"default:false"`
	AllowedCORSOrigins      pq.StringArray      `gorm:"type:text[]"`
	PostLogoutRedirectURIs  pq.StringArray      `gorm:"type:text[]"`
	JSONWebKeys             *jose.JSONWebKeySet `gorm:"type:jsonb"`
	SkipConsent             bool                `gorm:"default:false"`
	SubjectType             string              `gorm:"type:varchar(50);default:'public'"`
	BackchannelLogoutURI    string              `gorm:"type:text"`
	AccessTokenLifespan     string              `gorm:"type:varchar(50);default:''"`
	IDTokenLifespan         string              `gorm:"type:varchar(50);default:''"`
	RefreshTokenLifespan    string              `gorm:"type:varchar(50);default:''"`
	CreatedAt               time.Time           `gorm:"autoCreateTime"`
	UpdatedAt               time.Time           `gorm:"autoUpdateTime"`
}

func (OAuth2ClientGORM) TableName() string { return "o_auth2_clients" }

func (m *OAuth2ClientGORM) ToDomain() *entity.OAuth2Client {
	return &entity.OAuth2Client{
		ID:                      m.ID,
		TenantID:                m.TenantID,
		Name:                    m.Name,
		AppID:                   m.AppID,
		Secret:                  m.Secret,
		RedirectURIs:            m.RedirectURIs,
		GrantTypes:              m.GrantTypes,
		ResponseTypes:           m.ResponseTypes,
		ResponseModes:           m.ResponseModes,
		Scopes:                  m.Scopes,
		Audience:                m.Audience,
		Public:                  m.Public,
		TokenEndpointAuthMethod: m.TokenEndpointAuthMethod,
		EnforcePKCE:             m.EnforcePKCE,
		AllowedCORSOrigins:      m.AllowedCORSOrigins,
		PostLogoutRedirectURIs:  m.PostLogoutRedirectURIs,
		JSONWebKeys:             m.JSONWebKeys,
		SkipConsent:             m.SkipConsent,
		SubjectType:             m.SubjectType,
		BackchannelLogoutURI:    m.BackchannelLogoutURI,
		AccessTokenLifespan:     m.AccessTokenLifespan,
		IDTokenLifespan:         m.IDTokenLifespan,
		RefreshTokenLifespan:    m.RefreshTokenLifespan,
		CreatedAt:               m.CreatedAt,
		UpdatedAt:               m.UpdatedAt,
	}
}

func FromDomainOAuth2Client(e *entity.OAuth2Client) *OAuth2ClientGORM {
	return &OAuth2ClientGORM{
		ID:                      e.ID,
		TenantID:                e.TenantID,
		Name:                    e.Name,
		AppID:                   e.AppID,
		Secret:                  e.Secret,
		RedirectURIs:            e.RedirectURIs,
		GrantTypes:              e.GrantTypes,
		ResponseTypes:           e.ResponseTypes,
		ResponseModes:           e.ResponseModes,
		Scopes:                  e.Scopes,
		Audience:                e.Audience,
		Public:                  e.Public,
		TokenEndpointAuthMethod: e.TokenEndpointAuthMethod,
		EnforcePKCE:             e.EnforcePKCE,
		AllowedCORSOrigins:      e.AllowedCORSOrigins,
		PostLogoutRedirectURIs:  e.PostLogoutRedirectURIs,
		JSONWebKeys:             e.JSONWebKeys,
		SkipConsent:             e.SkipConsent,
		SubjectType:             e.SubjectType,
		BackchannelLogoutURI:    e.BackchannelLogoutURI,
		AccessTokenLifespan:     e.AccessTokenLifespan,
		IDTokenLifespan:         e.IDTokenLifespan,
		RefreshTokenLifespan:    e.RefreshTokenLifespan,
	}
}
