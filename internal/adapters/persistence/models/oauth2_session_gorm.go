package models

import (
	"time"

	"github.com/lib/pq"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
	"gorm.io/gorm"
)

type OAuth2SessionGORM struct {
	Signature       string         `gorm:"primaryKey;type:text"`
	TokenType       string         `gorm:"primaryKey;type:varchar(50)"`
	TenantID        string         `gorm:"type:varchar(255);not null;default:'default';index"`
	RequestID       string         `gorm:"type:varchar(255);not null;index"`
	ClientID        string         `gorm:"type:varchar(255);not null"`
	Subject         string         `gorm:"index"`
	TokenFamilyID   string         `gorm:"type:varchar(255);index"`
	SessionData     []byte         `gorm:"type:jsonb;not null"`
	Active          bool           `gorm:"default:true;index"`
	RequestData     []byte         `gorm:"type:jsonb"`
	ExpiresAt       time.Time      `gorm:"index"`
	GrantedScopes   pq.StringArray `gorm:"type:text[]"`
	GraceExpiresAt  *time.Time     `gorm:"index"`
	GraceUsedAt     *time.Time     `gorm:"index"`
	ReuseDetectedAt *time.Time     `gorm:"index"`
	UsedAt          *time.Time     `gorm:"index"`
	CreatedAt       time.Time      `gorm:"autoCreateTime"`
	UpdatedAt       time.Time      `gorm:"autoUpdateTime"`
	DeletedAt       gorm.DeletedAt `gorm:"index"`
}

func (OAuth2SessionGORM) TableName() string {
	return "o_auth2_sessions"
}

func (m *OAuth2SessionGORM) ToDomain() *entity.OAuth2Session {
	return &entity.OAuth2Session{
		Signature:       m.Signature,
		Type:            m.TokenType,
		TenantID:        m.TenantID,
		RequestID:       m.RequestID,
		ClientID:        m.ClientID,
		Subject:         m.Subject,
		TokenFamilyID:   m.TokenFamilyID,
		SessionData:     m.SessionData,
		Active:          m.Active,
		RequestData:     m.RequestData,
		ExpiresAt:       m.ExpiresAt,
		GrantedScopes:   m.GrantedScopes,
		GraceExpiresAt:  m.GraceExpiresAt,
		GraceUsedAt:     m.GraceUsedAt,
		ReuseDetectedAt: m.ReuseDetectedAt,
		UsedAt:          m.UsedAt,
		CreatedAt:       m.CreatedAt,
		UpdatedAt:       m.UpdatedAt,
	}
}

func FromDomainOAuth2Session(e *entity.OAuth2Session) *OAuth2SessionGORM {
	return &OAuth2SessionGORM{
		Signature:       e.Signature,
		TokenType:       e.Type,
		TenantID:        e.TenantID,
		RequestID:       e.RequestID,
		ClientID:        e.ClientID,
		Subject:         e.Subject,
		TokenFamilyID:   e.TokenFamilyID,
		SessionData:     e.SessionData,
		Active:          e.Active,
		RequestData:     e.RequestData,
		ExpiresAt:       e.ExpiresAt,
		GrantedScopes:   e.GrantedScopes,
		GraceExpiresAt:  e.GraceExpiresAt,
		GraceUsedAt:     e.GraceUsedAt,
		ReuseDetectedAt: e.ReuseDetectedAt,
		UsedAt:          e.UsedAt,
	}
}
