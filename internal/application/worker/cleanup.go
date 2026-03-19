package worker

import (
	"context"
	"time"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/pkg/logger"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// StartCleanupJob starts a background ticker to remove expired data.
func StartCleanupJob(db *gorm.DB, manager utils.KeyManager) {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			cleanupExpiredData(db)
		}
	}()

	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			logger.Log.Debug("Running Key Rotation check...")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)

			if err := manager.RotateKeys(ctx); err != nil {
				logger.Log.Error("Key Rotation Worker encountered an error", zap.Error(err))
			}

			cancel()
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
