package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/go-jose/go-jose/v4"
	"github.com/lib/pq"
)

type JSONB []byte

func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		s, okstr := value.(string)
		if !okstr {
			return errors.New("type assertion to []byte failed in JSONB Scanner")
		}
		b = []byte(s)
	}
	*j = make([]byte, len(b))
	copy(*j, b)
	return nil
}

func (j JSONB) Value() (driver.Value, error) {
	if len(j) == 0 {
		return nil, nil
	}
	return []byte(j), nil
}

type OAuth2ClientGORM struct {
	ID                          string         `gorm:"primaryKey;type:varchar(255)"`
	TenantID                    string         `gorm:"type:varchar(255);not null;index"`
	Name                        string         `gorm:"type:varchar(255);not null;default:'Unnamed Client'"`
	AppID                       string         `gorm:"index;type:varchar(255)"`
	Secret                      string         `gorm:"type:varchar(255)"`
	RedirectURIs                pq.StringArray `gorm:"type:text[]"`
	GrantTypes                  pq.StringArray `gorm:"type:text[]"`
	ResponseTypes               pq.StringArray `gorm:"type:text[]"`
	ResponseModes               pq.StringArray `gorm:"type:text[]"`
	Scopes                      pq.StringArray `gorm:"type:text[]"`
	Audience                    pq.StringArray `gorm:"type:text[]"`
	Public                      bool           `gorm:"default:false"`
	TokenEndpointAuthMethod     string         `gorm:"type:varchar(50);default:'client_secret_basic'"`
	EnforcePKCE                 bool           `gorm:"default:false"`
	AllowedCORSOrigins          pq.StringArray `gorm:"type:text[]"`
	PostLogoutRedirectURIs      pq.StringArray `gorm:"type:text[]"`
	JSONWebKeys                 JSONB          `gorm:"column:json_web_keys;type:jsonb"`
	JwksURI                     string         `gorm:"type:text"`
	IDTokenEncryptedResponseAlg string         `gorm:"type:varchar(50)"`
	IDTokenEncryptedResponseEnc string         `gorm:"type:varchar(50)"`
	SkipConsent                 bool           `gorm:"default:false"`
	SubjectType                 string         `gorm:"type:varchar(50);default:'public'"`
	BackchannelLogoutURI        string         `gorm:"type:text"`
	AccessTokenLifespan         string         `gorm:"type:varchar(50);default:''"`
	IDTokenLifespan             string         `gorm:"type:varchar(50);default:''"`
	RefreshTokenLifespan        string         `gorm:"type:varchar(50);default:''"`
	CreatedAt                   time.Time      `gorm:"autoCreateTime"`
	UpdatedAt                   time.Time      `gorm:"autoUpdateTime"`
}

func (OAuth2ClientGORM) TableName() string { return "o_auth2_clients" }

func (m *OAuth2ClientGORM) ToDomain() *model.OAuth2Client {
	var jwks *jose.JSONWebKeySet
	if len(m.JSONWebKeys) > 0 {
		var parsed jose.JSONWebKeySet
		if err := json.Unmarshal(m.JSONWebKeys, &parsed); err == nil {
			jwks = &parsed
		}
	}
	return &model.OAuth2Client{
		ID:                          m.ID,
		TenantID:                    m.TenantID,
		Name:                        m.Name,
		AppID:                       m.AppID,
		Secret:                      m.Secret,
		RedirectURIs:                m.RedirectURIs,
		GrantTypes:                  m.GrantTypes,
		ResponseTypes:               m.ResponseTypes,
		ResponseModes:               m.ResponseModes,
		Scopes:                      m.Scopes,
		Audience:                    m.Audience,
		Public:                      m.Public,
		TokenEndpointAuthMethod:     m.TokenEndpointAuthMethod,
		EnforcePKCE:                 m.EnforcePKCE,
		AllowedCORSOrigins:          m.AllowedCORSOrigins,
		PostLogoutRedirectURIs:      m.PostLogoutRedirectURIs,
		JSONWebKeys:                 jwks,
		JwksURI:                     m.JwksURI,
		IDTokenEncryptedResponseAlg: m.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc: m.IDTokenEncryptedResponseEnc,
		SkipConsent:                 m.SkipConsent,
		SubjectType:                 m.SubjectType,
		BackchannelLogoutURI:        m.BackchannelLogoutURI,
		AccessTokenLifespan:         m.AccessTokenLifespan,
		IDTokenLifespan:             m.IDTokenLifespan,
		RefreshTokenLifespan:        m.RefreshTokenLifespan,
		CreatedAt:                   m.CreatedAt,
		UpdatedAt:                   m.UpdatedAt,
	}
}

func FromDomainOAuth2Client(e *model.OAuth2Client) *OAuth2ClientGORM {
	var jwksBytes JSONB
	if e.JSONWebKeys != nil {
		b, _ := json.Marshal(e.JSONWebKeys)
		jwksBytes = JSONB(b)
	}
	return &OAuth2ClientGORM{
		ID:                          e.ID,
		TenantID:                    e.TenantID,
		Name:                        e.Name,
		AppID:                       e.AppID,
		Secret:                      e.Secret,
		RedirectURIs:                e.RedirectURIs,
		GrantTypes:                  e.GrantTypes,
		ResponseTypes:               e.ResponseTypes,
		ResponseModes:               e.ResponseModes,
		Scopes:                      e.Scopes,
		Audience:                    e.Audience,
		Public:                      e.Public,
		TokenEndpointAuthMethod:     e.TokenEndpointAuthMethod,
		EnforcePKCE:                 e.EnforcePKCE,
		AllowedCORSOrigins:          e.AllowedCORSOrigins,
		PostLogoutRedirectURIs:      e.PostLogoutRedirectURIs,
		JSONWebKeys:                 jwksBytes,
		JwksURI:                     e.JwksURI,
		IDTokenEncryptedResponseAlg: e.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc: e.IDTokenEncryptedResponseEnc,
		SkipConsent:                 e.SkipConsent,
		SubjectType:                 e.SubjectType,
		BackchannelLogoutURI:        e.BackchannelLogoutURI,
		AccessTokenLifespan:         e.AccessTokenLifespan,
		IDTokenLifespan:             e.IDTokenLifespan,
		RefreshTokenLifespan:        e.RefreshTokenLifespan,
	}
}
