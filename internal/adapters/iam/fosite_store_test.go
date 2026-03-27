package iam_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/internal/adapters/iam"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/pkg/consts"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	dbName := fmt.Sprintf("file:test_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(
		&models.OAuth2SessionGORM{},
		&models.OAuth2ClientGORM{},
		&models.BlacklistedJTIGORM{},
	)
	require.NoError(t, err)
	return db
}

func setupFositeStore(t *testing.T) (*gorm.DB, *iam.FositeStore) {
	db := setupTestDB(t)
	store := iam.NewFositeStore(db, nil, nil)
	return db, store
}

func getTenantCtx() context.Context {
	return context.WithValue(context.Background(), consts.ContextKeyTenantID, "tnt_test_01")
}

func TestFositeStore_GracePeriod(t *testing.T) {
	t.Parallel()
	db, _ := setupFositeStore(t)
	_ = getTenantCtx()

	session := models.OAuth2SessionGORM{
		Signature:   "rt_signature_123",
		RequestID:   "req_123",
		ClientID:    "client_1",
		TokenType:   "refresh_token",
		TenantID:    "tnt_test_01",
		Active:      true,
		SessionData: []byte(`{}`),
		CreatedAt:   time.Now(),
	}
	require.NoError(t, db.Create(&session).Error)

	graceExp := time.Now().UTC().Add(time.Minute * 5)
	err := db.Model(&models.OAuth2SessionGORM{}).
		Where("signature = ? AND token_type = ? AND tenant_id = ?", "rt_signature_123", "refresh_token", "tnt_test_01").
		Updates(map[string]interface{}{
			"grace_expires_at": graceExp,
		}).Error
	require.NoError(t, err)

	var updatedSession models.OAuth2SessionGORM
	err = db.Where("signature = ? AND token_type = ?", "rt_signature_123", "refresh_token").First(&updatedSession).Error
	require.NoError(t, err)

	assert.NotNil(t, updatedSession.GraceExpiresAt)
	assert.WithinDuration(t, graceExp, *updatedSession.GraceExpiresAt, time.Second*2)
}

func TestFositeStore_FamilyKill(t *testing.T) {
	t.Parallel()
	db, _ := setupFositeStore(t)

	familyID := "family_hash_abc123"
	tenantID := "tnt_test_01"

	sessions := []models.OAuth2SessionGORM{
		{Signature: "rt_1", RequestID: "req_1", ClientID: "client_1", SessionData: []byte(`{}`), TokenType: "refresh_token", TokenFamilyID: familyID, TenantID: tenantID, Active: true},
		{Signature: "at_1", RequestID: "req_1", ClientID: "client_1", SessionData: []byte(`{}`), TokenType: "access_token", TokenFamilyID: familyID, TenantID: tenantID, Active: true},
		{Signature: "rt_2", RequestID: "req_2", ClientID: "client_1", SessionData: []byte(`{}`), TokenType: "refresh_token", TokenFamilyID: familyID, TenantID: tenantID, Active: true}, // Rotated
	}
	require.NoError(t, db.Create(&sessions).Error)

	err := db.Model(&models.OAuth2SessionGORM{}).
		Where("token_family_id = ? AND tenant_id = ?", familyID, tenantID).
		Updates(map[string]interface{}{"active": false}).Error
	require.NoError(t, err)

	var verifySessions []models.OAuth2SessionGORM
	db.Where("token_family_id = ?", familyID).Find(&verifySessions)
	require.Len(t, verifySessions, 3)

	for _, s := range verifySessions {
		assert.False(t, s.Active, "Token %s must be inactive after family kill", s.Signature)
	}
}

func TestFositeStore_TypeSafety(t *testing.T) {
	t.Parallel()
	db, _ := setupFositeStore(t)
	tenantID := "tnt_test_01"

	sharedSignature := "shared_edge_case_sig"

	sessions := []models.OAuth2SessionGORM{
		{Signature: sharedSignature, RequestID: "req_3", ClientID: "client_1", SessionData: []byte(`{}`), TokenType: "access_token", TenantID: tenantID, Active: true},
		{Signature: sharedSignature, RequestID: "req_4", ClientID: "client_1", SessionData: []byte(`{}`), TokenType: "refresh_token", TenantID: tenantID, Active: true},
	}
	require.NoError(t, db.Create(&sessions).Error)

	err := db.Model(&models.OAuth2SessionGORM{}).
		Where("signature = ? AND token_type = ? AND tenant_id = ?", sharedSignature, "access_token", tenantID).
		Updates(map[string]interface{}{"active": false}).Error
	require.NoError(t, err)

	var at, rt models.OAuth2SessionGORM
	db.Where("signature = ? AND token_type = ?", sharedSignature, "access_token").First(&at)
	db.Where("signature = ? AND token_type = ?", sharedSignature, "refresh_token").First(&rt)

	assert.False(t, at.Active, "Access token must be revoked")
	assert.True(t, rt.Active, "Refresh token must remain active (Type Safety boundary enforced)")
}
