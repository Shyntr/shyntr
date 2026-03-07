package audit

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nevzatcirak/shyntr/internal/adapters/persistence/models"
	"github.com/nevzatcirak/shyntr/internal/application/port"
	"gorm.io/gorm"
)

type AuditLogger struct {
	db *gorm.DB
}

func NewAuditLogger(db *gorm.DB) port.AuditLogger {
	return &AuditLogger{db: db}
}

func (a *AuditLogger) Log(tenantID, actor, action, ip, ua string, details map[string]interface{}) {
	go func() {
		var detailsBytes []byte
		if details != nil {
			detailsBytes, _ = json.Marshal(details)
		}

		logEntry := models.AuditLogGORM{
			ID:        "aud_" + strings.ReplaceAll(uuid.New().String(), "-", ""),
			TenantID:  tenantID,
			Actor:     actor,
			Action:    action,
			IPAddress: ip,
			UserAgent: ua,
			Details:   detailsBytes,
			CreatedAt: time.Now(),
		}
		a.db.Create(&logEntry)
	}()
}

func (a *AuditLogger) LogWithoutIP(tenantID, actor, action string, details map[string]interface{}) {
	go func() {
		var detailsBytes []byte
		if details != nil {
			detailsBytes, _ = json.Marshal(details)
		}

		logEntry := models.AuditLogGORM{
			ID:        "aud_" + strings.ReplaceAll(uuid.New().String(), "-", ""),
			TenantID:  tenantID,
			Actor:     actor,
			Action:    action,
			IPAddress: "",
			UserAgent: "",
			Details:   detailsBytes,
			CreatedAt: time.Now(),
		}
		a.db.Create(&logEntry)
	}()
}
