package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/internal/data/repository"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func setupSAMLStore(t *testing.T) (*repository.SAMLRepository, *gorm.DB) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}

	err = db.AutoMigrate(
		&models.SAMLReplayCache{},
		&models.SAMLConnection{},
		&models.SAMLClient{},
	)
	if err != nil {
		t.Fatalf("failed to migrate database: %v", err)
	}

	return repository.NewSAMLRepository(db), db
}

func TestSAMLReplayCache_Security(t *testing.T) {
	repo, db := setupSAMLStore(t)
	ctx := context.Background()

	tenantID := "secure-tenant-1"
	messageID := "id-crypto-random-123456"
	expiration := 5 * time.Minute

	defer db.Exec("DELETE FROM saml_replay_caches")

	t.Run("Valid First Request (Success)", func(t *testing.T) {
		err := repo.CheckAndSaveMessageID(ctx, messageID, tenantID, expiration)
		assert.NoError(t, err, "First use of message ID should be successful")
	})

	t.Run("Replay Attack (Failure)", func(t *testing.T) {
		err := repo.CheckAndSaveMessageID(ctx, messageID, tenantID, expiration)

		assert.Error(t, err, "Replay attack should be blocked")
		assert.Contains(t, err.Error(), "replay detected")
	})

	t.Run("Expired Cache Cleanup Validation", func(t *testing.T) {
		expiredMessageID := "id-expired-999"

		db.Create(&models.SAMLReplayCache{
			MessageID: expiredMessageID,
			TenantID:  tenantID,
			ExpiresAt: time.Now().Add(-1 * time.Minute),
			CreatedAt: time.Now(),
		})

		_ = repo.CheckAndSaveMessageID(ctx, "id-trigger", tenantID, expiration)

		time.Sleep(50 * time.Millisecond)

		err := repo.CheckAndSaveMessageID(ctx, expiredMessageID, tenantID, expiration)
		assert.NoError(t, err, "Expired messages should be cleaned up from DB")
	})
}
