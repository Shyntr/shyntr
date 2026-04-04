package audit

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/google/uuid"
	"go.uber.org/zap"
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
		detailsBytes := []byte("{}")

		if details != nil {
			marshaled, err := json.Marshal(details)
			if err != nil {
				logger.Log.Error("Failed to marshal audit log details",
					zap.Error(err),
					zap.String("tenant_id", tenantID),
					zap.String("actor", actor),
					zap.String("action", action),
				)
			} else {
				detailsBytes = marshaled
			}
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

		if err := a.db.Create(&logEntry).Error; err != nil {
			logger.Log.Error("Failed to persist audit log",
				zap.Error(err),
				zap.String("tenant_id", tenantID),
				zap.String("actor", actor),
				zap.String("action", action),
				zap.String("audit_id", logEntry.ID),
			)
		}
	}()
}
