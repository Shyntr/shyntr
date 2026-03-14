package models

import (
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
	return &model.AuditLog{
		ID:        m.ID,
		TenantID:  m.TenantID,
		Actor:     m.Actor,
		Action:    m.Action,
		IPAddress: m.IPAddress,
		UserAgent: m.UserAgent,
		Details:   m.Details,
		CreatedAt: m.CreatedAt,
	}
}

func FromDomainAuditLog(e *model.AuditLog) *AuditLogGORM {
	return &AuditLogGORM{
		ID:        e.ID,
		TenantID:  e.TenantID,
		Actor:     e.Actor,
		Action:    e.Action,
		IPAddress: e.IPAddress,
		UserAgent: e.UserAgent,
		Details:   e.Details,
		CreatedAt: e.CreatedAt,
	}
}
