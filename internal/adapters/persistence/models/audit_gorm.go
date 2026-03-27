package models

import (
	"encoding/json"
	"time"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

type AuditLogGORM struct {
	ID        string    `gorm:"primaryKey;type:varchar(255)"`
	TenantID  string    `gorm:"type:varchar(255);not null;index"`
	Actor     string    `gorm:"type:varchar(255)"`
	Action    string    `gorm:"type:varchar(255);not null;index"`
	IPAddress string    `gorm:"type:varchar(45)"`
	UserAgent string    `gorm:"type:text"`
	Details   []byte    `gorm:"type:jsonb"`
	CreatedAt time.Time `gorm:"autoCreateTime;index"`
}

func (AuditLogGORM) TableName() string { return "audit_logs" }

func (m *AuditLogGORM) ToDomain() *model.AuditLog {
	var details map[string]interface{}
	if m.Details != nil {
		_ = json.Unmarshal(m.Details, &details)
	}
	return &model.AuditLog{
		ID:        m.ID,
		TenantID:  m.TenantID,
		Actor:     m.Actor,
		Action:    m.Action,
		IPAddress: m.IPAddress,
		UserAgent: m.UserAgent,
		Details:   details,
		CreatedAt: m.CreatedAt,
	}
}

func FromDomainAuditLog(e *model.AuditLog) *AuditLogGORM {
	var detailsBytes []byte
	if e.Details != nil {
		detailsBytes, _ = json.Marshal(e.Details)
	}
	return &AuditLogGORM{
		ID:        e.ID,
		TenantID:  e.TenantID,
		Actor:     e.Actor,
		Action:    e.Action,
		IPAddress: e.IPAddress,
		UserAgent: e.UserAgent,
		Details:   detailsBytes,
		CreatedAt: e.CreatedAt,
	}
}
