package models

import (
	"time"

	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type LoginRequestGORM struct {
	ID                string         `gorm:"primaryKey;type:varchar(255)"`
	TenantID          string         `gorm:"type:varchar(255);not null;index"`
	ClientID          string         `gorm:"type:varchar(255);not null"`
	Subject           string         `gorm:"type:varchar(255)"`
	RequestedScope    pq.StringArray `gorm:"type:text[]"`
	RequestedAudience pq.StringArray `gorm:"type:text[]"`
	RequestURL        string         `gorm:"type:text"`
	Protocol          string         `gorm:"type:varchar(50)"`
	SAMLRequestID     string         `gorm:"type:varchar(255)"`
	ClientIP          string         `gorm:"type:varchar(45)"`
	Context           []byte         `gorm:"type:jsonb"`
	Authenticated     bool           `gorm:"default:false"`
	Remember          bool           `gorm:"default:false"`
	RememberFor       int            `gorm:"default:0"`
	Active            bool           `gorm:"default:true;index"`
	Skip              bool           `gorm:"default:false"`
	SessionID         string         `gorm:"type:varchar(255);index"`
	CreatedAt         time.Time      `gorm:"autoCreateTime"`
	UpdatedAt         time.Time      `gorm:"autoUpdateTime"`
	DeletedAt         gorm.DeletedAt `gorm:"index"`
}

func (LoginRequestGORM) TableName() string { return "login_requests" }

func (m *LoginRequestGORM) ToDomain() *model.LoginRequest {
	return &model.LoginRequest{
		ID:                m.ID,
		TenantID:          m.TenantID,
		ClientID:          m.ClientID,
		Subject:           m.Subject,
		RequestedScope:    m.RequestedScope,
		RequestedAudience: m.RequestedAudience,
		RequestURL:        m.RequestURL,
		Protocol:          m.Protocol,
		SAMLRequestID:     m.SAMLRequestID,
		ClientIP:          m.ClientIP,
		Context:           m.Context,
		Authenticated:     m.Authenticated,
		Remember:          m.Remember,
		RememberFor:       m.RememberFor,
		Active:            m.Active,
		Skip:              m.Skip,
		SessionID:         m.SessionID,
		CreatedAt:         m.CreatedAt,
		UpdatedAt:         m.UpdatedAt,
	}
}

func ToDomainLoginRequestList(eList []LoginRequestGORM) []model.LoginRequest {
	result := make([]model.LoginRequest, 0, len(eList))

	for _, m := range eList {
		result = append(result, model.LoginRequest{
			ID:                m.ID,
			TenantID:          m.TenantID,
			ClientID:          m.ClientID,
			Subject:           m.Subject,
			RequestedScope:    m.RequestedScope,
			RequestedAudience: m.RequestedAudience,
			RequestURL:        m.RequestURL,
			Protocol:          m.Protocol,
			SAMLRequestID:     m.SAMLRequestID,
			ClientIP:          m.ClientIP,
			Context:           m.Context,
			Authenticated:     m.Authenticated,
			Remember:          m.Remember,
			RememberFor:       m.RememberFor,
			Active:            m.Active,
			Skip:              m.Skip,
			SessionID:         m.SessionID,
			CreatedAt:         m.CreatedAt,
			UpdatedAt:         m.UpdatedAt,
		})
	}

	return result
}

func FromDomainLoginRequest(e *model.LoginRequest) *LoginRequestGORM {
	return &LoginRequestGORM{
		ID:                e.ID,
		TenantID:          e.TenantID,
		ClientID:          e.ClientID,
		Subject:           e.Subject,
		RequestedScope:    e.RequestedScope,
		RequestedAudience: e.RequestedAudience,
		RequestURL:        e.RequestURL,
		Protocol:          e.Protocol,
		SAMLRequestID:     e.SAMLRequestID,
		ClientIP:          e.ClientIP,
		Context:           e.Context,
		Authenticated:     e.Authenticated,
		Remember:          e.Remember,
		RememberFor:       e.RememberFor,
		Active:            e.Active,
		Skip:              e.Skip,
		SessionID:         e.SessionID,
	}
}

func LoginRequestToUpdateMap(req *model.LoginRequest) map[string]interface{} {
	return map[string]interface{}{
		"subject":         req.Subject,
		"authenticated":   req.Authenticated,
		"remember":        req.Remember,
		"remember_for":    req.RememberFor,
		"active":          req.Active,
		"skip":            req.Skip,
		"context":         req.Context,
		"saml_request_id": req.SAMLRequestID,
		"session_id":      req.SessionID,
	}
}

type ConsentRequestGORM struct {
	ID                string         `gorm:"primaryKey;type:varchar(255)"`
	LoginChallenge    string         `gorm:"index"`
	ClientID          string         `gorm:"type:varchar(255);not null"`
	Subject           string         `gorm:"type:varchar(255);not null"`
	RequestedScope    pq.StringArray `gorm:"type:text[]"`
	RequestedAudience pq.StringArray `gorm:"type:text[]"`
	GrantedScope      pq.StringArray `gorm:"type:text[]"`
	GrantedAudience   pq.StringArray `gorm:"type:text[]"`
	RequestURL        string         `gorm:"type:text"`
	Context           []byte         `gorm:"type:jsonb"`
	Skip              bool           `gorm:"default:false"`
	Authenticated     bool           `gorm:"default:false"`
	Remember          bool           `gorm:"default:false"`
	RememberFor       int            `gorm:"default:0"`
	Active            bool           `gorm:"default:true;index"`
	CreatedAt         time.Time      `gorm:"autoCreateTime"`
	UpdatedAt         time.Time      `gorm:"autoUpdateTime"`
	DeletedAt         gorm.DeletedAt `gorm:"index"`
}

func (ConsentRequestGORM) TableName() string { return "consent_requests" }

func (m *ConsentRequestGORM) ToDomain() *model.ConsentRequest {
	return &model.ConsentRequest{
		ID:                m.ID,
		LoginChallenge:    m.LoginChallenge,
		ClientID:          m.ClientID,
		Subject:           m.Subject,
		RequestedScope:    m.RequestedScope,
		RequestedAudience: m.RequestedAudience,
		GrantedScope:      m.GrantedScope,
		GrantedAudience:   m.GrantedAudience,
		RequestURL:        m.RequestURL,
		Context:           m.Context,
		Skip:              m.Skip,
		Authenticated:     m.Authenticated,
		Remember:          m.Remember,
		RememberFor:       m.RememberFor,
		Active:            m.Active,
		CreatedAt:         m.CreatedAt,
		UpdatedAt:         m.UpdatedAt,
	}
}

func FromDomainConsentRequest(e *model.ConsentRequest) *ConsentRequestGORM {
	return &ConsentRequestGORM{
		ID:                e.ID,
		LoginChallenge:    e.LoginChallenge,
		ClientID:          e.ClientID,
		Subject:           e.Subject,
		RequestedScope:    e.RequestedScope,
		RequestedAudience: e.RequestedAudience,
		GrantedScope:      e.GrantedScope,
		GrantedAudience:   e.GrantedAudience,
		RequestURL:        e.RequestURL,
		Context:           e.Context,
		Skip:              e.Skip,
		Authenticated:     e.Authenticated,
		Remember:          e.Remember,
		RememberFor:       e.RememberFor,
		Active:            e.Active,
	}
}

func ConsentRequestToUpdateMap(req *model.ConsentRequest) map[string]interface{} {
	return map[string]interface{}{
		"active":           req.Active,
		"authenticated":    req.Authenticated,
		"granted_scope":    pq.StringArray(req.GrantedScope),
		"granted_audience": pq.StringArray(req.GrantedAudience),
		"remember":         req.Remember,
		"remember_for":     req.RememberFor,
		"context":          req.Context,
		"skip":             req.Skip,
	}
}
