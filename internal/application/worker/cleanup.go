package worker

import (
	"time"

	"github.com/nevzatcirak/shyntr/internal/adapters/persistence/models"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// StartCleanupJob starts a background ticker to remove expired data.
func StartCleanupJob(db *gorm.DB) {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			cleanupExpiredData(db)
		}
	}()
	logger.Log.Info("Background cleanup job started")
}

func cleanupExpiredData(db *gorm.DB) {
	now := time.Now()
	expirationHorizon := now.Add(-2 * time.Hour)

	if err := db.Where("expires_at < ?", now).Delete(&models.OAuth2SessionGORM{}).Error; err != nil {
		logger.Log.Error("Cleanup failed: OAuth2Session", zap.Error(err))
	}

	if err := db.Where("expires_at < ?", now).Delete(&models.BlacklistedJTIGORM{}).Error; err != nil {
		logger.Log.Error("Cleanup failed: BlacklistedJTI", zap.Error(err))
	}

	if err := db.Where("expires_at < ?", now).Delete(&models.SAMLReplayCache{}).Error; err != nil {
		logger.Log.Error("Cleanup failed: SAMLReplayCache", zap.Error(err))
	}

	if err := db.Where("created_at < ?", expirationHorizon).Delete(&models.LoginRequestGORM{}).Error; err != nil {
		logger.Log.Error("Cleanup failed: LoginRequest", zap.Error(err))
	}

	if err := db.Where("created_at < ?", expirationHorizon).Delete(&models.ConsentRequestGORM{}).Error; err != nil {
		logger.Log.Error("Cleanup failed: ConsentRequest", zap.Error(err))
	}

	webhookRetention := now.Add(-7 * 24 * time.Hour)
	if err := db.Where("created_at < ?", webhookRetention).Delete(&models.WebhookEventGORM{}).Error; err != nil {
		logger.Log.Error("Cleanup failed: WebhookEvent", zap.Error(err))
	}

	logger.Log.Debug("Cleanup cycle completed")
}
