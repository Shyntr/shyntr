package audit

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"gorm.io/gorm"
)

func LogAsync(db *gorm.DB, tenantID, actor, action, ip, ua string, details map[string]interface{}) {
	go func() {
		var detailsBytes []byte
		if details != nil {
			detailsBytes, _ = json.Marshal(details)
		}

		logEntry := models.AuditLog{
			ID:        "aud_" + strings.ReplaceAll(uuid.New().String(), "-", ""),
			TenantID:  tenantID,
			Actor:     actor,
			Action:    action,
			IPAddress: ip,
			UserAgent: ua,
			Details:   detailsBytes,
			CreatedAt: time.Now(),
		}
		db.Create(&logEntry)
	}()
}
