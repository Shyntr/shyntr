package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/internal/data/repository"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func setupStore(t *testing.T) (*repository.SQLStore, *gorm.DB) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}

	db.AutoMigrate(
		&models.OAuth2Session{},
		&models.BlacklistedJTI{},
	)

	return repository.NewSQLStore(db), db
}

func TestSQLStore_RevokeRefreshTokenMaybeGracePeriod(t *testing.T) {
	store, db := setupStore(t)
	ctx := context.Background()

	signature := "test-signature"
	reqID := "req-123"
	originalExpiry := time.Now().Add(1 * time.Hour)

	session := models.OAuth2Session{
		Signature: signature,
		RequestID: reqID,
		ClientID:  "client-1",
		Type:      "refresh_token",
		Active:    true,
		ExpiresAt: originalExpiry,
	}
	db.Create(&session)

	err := store.RevokeRefreshTokenMaybeGracePeriod(ctx, reqID, signature)
	assert.NoError(t, err)

	var updatedSession models.OAuth2Session
	result := db.First(&updatedSession, "signature = ?", signature)
	assert.NoError(t, result.Error)

	// Expiry should be much less than the original 1 hour
	// It should be around time.Now() + 15s
	timeUntilExpiry := time.Until(updatedSession.ExpiresAt)
	assert.True(t, timeUntilExpiry < 20*time.Second, "Expiry should be shortened for grace period")
	assert.True(t, timeUntilExpiry > 0, "Token should still be valid for a few seconds")
	assert.True(t, updatedSession.Active, "Token should remain active during grace period")
}

func TestSQLStore_ClientAssertionJWTValid(t *testing.T) {
	store, _ := setupStore(t)
	ctx := context.Background()
	jti := "unique-jti-123"
	exp := time.Now().Add(1 * time.Hour)

	err := store.ClientAssertionJWTValid(ctx, jti)
	assert.NoError(t, err)

	err = store.SetClientAssertionJWT(ctx, jti, exp)
	assert.NoError(t, err)

	err = store.ClientAssertionJWTValid(ctx, jti)
	assert.Error(t, err)
	assert.Equal(t, fosite.ErrJTIKnown, err)
}
