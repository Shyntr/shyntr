package models

import (
	"time"
)

type AuditLog struct {
	ID        string    `json:"id" gorm:"primaryKey;type:varchar(50)"`
	TenantID  string    `json:"tenant_id" gorm:"index"`
	Actor     string    `json:"actor" gorm:"index"`
	Action    string    `json:"action" gorm:"index"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	Details   []byte    `json:"details" gorm:"type:jsonb"`
	CreatedAt time.Time `json:"created_at" gorm:"index"`
}
