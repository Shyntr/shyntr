package repository

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupAuditTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditLogGORM{}))
	return db
}

func TestGetAuthActivityCounts_SafetyAndDoubleCounting(t *testing.T) {
	db := setupAuditTestDB(t)
	repo := NewAuditLogRepository(db)
	ctx := context.Background()
	now := time.Now()

	// 1. Test safety against unexpected protocols
	detailsUnknown := map[string]interface{}{"protocol": "unknown_proto"}
	detailsUnknownJSON, _ := json.Marshal(detailsUnknown)
	db.Create(&models.AuditLogGORM{
		ID:        "a1",
		Action:    "auth.login.accept",
		Details:   detailsUnknownJSON,
		CreatedAt: now,
	})

	// 2. Test LDAP success double-counting (protocol=ldap, provider_type=ldap)
	detailsLDAP := map[string]interface{}{"protocol": "ldap", "provider_type": "ldap"}
	detailsLDAPJSON, _ := json.Marshal(detailsLDAP)
	db.Create(&models.AuditLogGORM{
		ID:        "a2",
		Action:    "auth.login.accept",
		Details:   detailsLDAPJSON,
		CreatedAt: now,
	})

	// 3. Test OIDC via LDAP success (protocol=oidc, provider_type=ldap)
	detailsOIDCLDAP := map[string]interface{}{"protocol": "oidc", "provider_type": "ldap"}
	detailsOIDCLDAPJSON, _ := json.Marshal(detailsOIDCLDAP)
	db.Create(&models.AuditLogGORM{
		ID:        "a3",
		Action:    "auth.login.accept",
		Details:   detailsOIDCLDAPJSON,
		CreatedAt: now,
	})

	counts, totalSuccess, _, err := repo.GetAuthActivityCounts(ctx, now.Add(-1*time.Hour))
	require.NoError(t, err)

	assert.Equal(t, int64(3), totalSuccess)

	// 'unknown_proto' should have been initialized and incremented safely
	require.Contains(t, counts, "unknown_proto")
	assert.Equal(t, int64(1), counts["unknown_proto"]["success"])

	// 'ldap' success:
	// a2 (protocol=ldap, provider_type=ldap) -> should increment ldap success once
	// a3 (protocol=oidc, provider_type=ldap) -> should increment oidc success AND ldap success
	assert.Equal(t, int64(2), counts["ldap"]["success"], "LDAP successes should be 2 (a2 and a3)")
	assert.Equal(t, int64(1), counts["oidc"]["success"], "OIDC successes should be 1 (a3)")
}

func TestGetAuthFailureMetrics_Safety(t *testing.T) {
	db := setupAuditTestDB(t)
	repo := NewAuditLogRepository(db)
	ctx := context.Background()
	now := time.Now()

	// Test safety against unexpected protocols in failure metrics
	detailsUnknown := map[string]interface{}{"protocol": "unknown_proto", "error_name": "invalid_request"}
	detailsUnknownJSON, _ := json.Marshal(detailsUnknown)
	db.Create(&models.AuditLogGORM{
		ID:        "f1",
		Action:    "auth.login.reject",
		Details:   detailsUnknownJSON,
		CreatedAt: now,
	})

	metrics, err := repo.GetAuthFailureMetrics(ctx, now.Add(-1*time.Hour))
	require.NoError(t, err)

	assert.Equal(t, int64(1), metrics.Totals.Failure)
	require.Contains(t, metrics.Protocols, "unknown_proto")
	assert.Equal(t, int64(1), metrics.Protocols["unknown_proto"].Failure)
	assert.Equal(t, "invalid_request", metrics.Protocols["unknown_proto"].TopReason)
}
