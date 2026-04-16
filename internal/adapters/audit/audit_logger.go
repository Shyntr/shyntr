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
	db  *gorm.DB
	log *zap.Logger
}

func NewAuditLogger(db *gorm.DB) port.AuditLogger {
	return &AuditLogger{db: db, log: logger.Log}
}

// NewAuditLoggerWithZap creates an AuditLogger with a caller-supplied Zap logger.
// Use this in tests to direct structured audit output to a bytes.Buffer sink.
func NewAuditLoggerWithZap(db *gorm.DB, log *zap.Logger) port.AuditLogger {
	return &AuditLogger{db: db, log: log}
}

func (a *AuditLogger) Log(tenantID, actor, action, ip, ua string, details map[string]interface{}) {
	go func() {
		// Emit a structured Zap log so callers (including tests) can observe audit events.
		if a.log != nil {
			fields := []zap.Field{
				zap.String("event", action),
				zap.String("tenant_id", tenantID),
				zap.String("user_identifier", actor),
				zap.String("client_ip", ip),
				zap.String("user_agent", ua),
			}
			for k, v := range details {
				fields = append(fields, zap.Any(k, v))
			}
			a.log.Info("audit.event", fields...)
		}

		detailsBytes := []byte("{}")

		if details != nil {
			marshaled, err := json.Marshal(details)
			if err != nil {
				if a.log != nil {
					a.log.Error("Failed to marshal audit log details",
						zap.Error(err),
						zap.String("tenant_id", tenantID),
						zap.String("actor", actor),
						zap.String("action", action),
					)
				}
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
			if a.log != nil {
				a.log.Error("Failed to persist audit log",
					zap.Error(err),
					zap.String("tenant_id", tenantID),
					zap.String("actor", actor),
					zap.String("action", action),
					zap.String("audit_id", logEntry.ID),
				)
			}
		}
	}()
}
