package worker

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func setupWorkerDB(t *testing.T) *gorm.DB {
	logger.InitLogger("info")
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}

	db.AutoMigrate(
		&models.OAuth2Session{},
		&models.BlacklistedJTI{},
		&models.SAMLReplayCache{},
		&models.LoginRequest{},
		&models.ConsentRequest{},
	)
	return db
}

func TestCleanupExpiredData_RetentionPolicies(t *testing.T) {
	db := setupWorkerDB(t)

	now := time.Now()

	db.Create(&models.OAuth2Session{Signature: "expired-token", ExpiresAt: now.Add(-1 * time.Hour)})
	db.Create(&models.BlacklistedJTI{JTI: "expired-jti", ExpiresAt: now.Add(-1 * time.Hour)})
	db.Create(&models.SAMLReplayCache{MessageID: "expired-msg", ExpiresAt: now.Add(-1 * time.Hour)})

	db.Create(&models.LoginRequest{ID: "expired-login", CreatedAt: now.Add(-3 * time.Hour)})
	db.Create(&models.ConsentRequest{ID: "expired-consent", CreatedAt: now.Add(-3 * time.Hour)})

	db.Create(&models.OAuth2Session{Signature: "active-token", ExpiresAt: now.Add(1 * time.Hour)})
	db.Create(&models.BlacklistedJTI{JTI: "active-jti", ExpiresAt: now.Add(1 * time.Hour)})
	db.Create(&models.SAMLReplayCache{MessageID: "active-msg", ExpiresAt: now.Add(1 * time.Hour)})

	db.Create(&models.LoginRequest{ID: "active-login", CreatedAt: now.Add(-1 * time.Hour)})
	db.Create(&models.ConsentRequest{ID: "active-consent", CreatedAt: now.Add(-1 * time.Hour)})

	cleanupExpiredData(db)

	var count int64

	db.Model(&models.OAuth2Session{}).Where("signature = ?", "expired-token").Count(&count)
	assert.Equal(t, int64(0), count, "Expired OAuth2Session was not deleted")

	db.Model(&models.LoginRequest{}).Where("id = ?", "expired-login").Count(&count)
	assert.Equal(t, int64(0), count, "Expired LoginRequest (older than 2h) was not deleted")

	db.Model(&models.OAuth2Session{}).Where("signature = ?", "active-token").Count(&count)
	assert.Equal(t, int64(1), count, "Active OAuth2Session was incorrectly deleted!")

	db.Model(&models.LoginRequest{}).Where("id = ?", "active-login").Count(&count)
	assert.Equal(t, int64(1), count, "Active LoginRequest was incorrectly deleted!")

	db.Model(&models.SAMLReplayCache{}).Where("message_id = ?", "active-msg").Count(&count)
	assert.Equal(t, int64(1), count, "Active SAMLReplayCache was incorrectly deleted!")
}
