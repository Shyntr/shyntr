package worker

import (
	"time"

	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// StartCleanupJob starts a background ticker to remove expired sessions.
func StartCleanupJob(db *gorm.DB) {
	ticker := time.NewTicker(1 * time.Hour) // Run every hour
	go func() {
		for range ticker.C {
			cleanupExpiredSessions(db)
		}
	}()
	logger.Log.Info("Background cleanup job started")
}

func cleanupExpiredSessions(db *gorm.DB) {
	result := db.Where("expires_at < ?", time.Now()).Delete(&models.OAuth2Session{})
	if result.Error != nil {
		logger.Log.Error("Failed to cleanup expired sessions", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Log.Info("Cleaned up expired sessions", zap.Int64("count", result.RowsAffected))
	}
}
