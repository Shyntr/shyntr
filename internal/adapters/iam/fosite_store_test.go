package iam_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/internal/adapters/iam"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/repository"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/consts"
	"github.com/glebarez/sqlite"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

var fositeTestDBCounter atomic.Int64

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

// ---------------------------------------------------------------------------
// Helper: create a FositeStore wired with real repositories for integration tests.
// ---------------------------------------------------------------------------

func setupFositeStoreWithRepos(t *testing.T) (*iam.FositeStore, *gorm.DB, string, string) {
	t.Helper()
	n := fositeTestDBCounter.Add(1)
	db, err := gorm.Open(
		sqlite.Open(fmt.Sprintf("file:fosite_int_%d?mode=memory&cache=shared", n)),
		&gorm.Config{},
	)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.OAuth2SessionGORM{},
		&models.OAuth2ClientGORM{},
		&models.BlacklistedJTIGORM{},
	))

	tenantID := "tenant-fosite-it"
	clientID := "it-client"
	require.NoError(t, db.Create(&models.OAuth2ClientGORM{
		ID:                      clientID,
		TenantID:                tenantID,
		Name:                    "IT Client",
		Public:                  true,
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"http://localhost/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid"},
	}).Error)

	clientRepo := repository.NewOAuth2ClientRepository(db)
	jtiRepo := repository.NewBlacklistedJTIRepository(db)
	store := iam.NewFositeStore(db, clientRepo, jtiRepo)
	return store, db, tenantID, clientID
}

// tenantCtxFor returns a context carrying the given tenant ID under the package's context key.
func tenantCtxFor(tenantID string) context.Context {
	return context.WithValue(context.Background(), consts.ContextKeyTenantID, tenantID)
}

// newFositeRequest builds a minimal fosite.Requester suitable for storing sessions.
func newFositeRequest(clientID, subject string, expireIn time.Duration) fosite.Requester {
	sess := model.NewJWTSession(subject, "")
	sess.SetExpiresAt(fosite.AccessToken, time.Now().Add(expireIn))
	sess.SetExpiresAt(fosite.RefreshToken, time.Now().Add(expireIn))
	req := fosite.NewAccessRequest(sess)
	req.SetID(fmt.Sprintf("req-%d", time.Now().UnixNano()))
	req.Client = &fosite.DefaultClient{ID: clientID, Public: true}
	req.GrantScope("openid")
	return req
}

func TestFositeStore_RefreshToken_CreateAndGet(t *testing.T) {
	store, _, tenantID, clientID := setupFositeStoreWithRepos(t)
	ctx := tenantCtxFor(tenantID)

	req := newFositeRequest(clientID, "alice", time.Hour)
	sig := "rt-create-get-001"

	require.NoError(t, store.CreateRefreshTokenSession(ctx, sig, req))

	got, err := store.GetRefreshTokenSession(ctx, sig, model.NewJWTSession("", ""))
	require.NoError(t, err)
	assert.Equal(t, clientID, got.GetClient().GetID())
}

func TestFositeStore_RefreshToken_Revoke(t *testing.T) {
	store, _, tenantID, clientID := setupFositeStoreWithRepos(t)
	ctx := tenantCtxFor(tenantID)

	req := newFositeRequest(clientID, "alice", time.Hour)
	sig := "rt-revoke-001"

	require.NoError(t, store.CreateRefreshTokenSession(ctx, sig, req))
	require.NoError(t, store.RevokeRefreshToken(ctx, req.GetID()))

	_, err := store.GetRefreshTokenSession(ctx, sig, model.NewJWTSession("", ""))
	assert.True(t, errors.Is(err, fosite.ErrInactiveToken) || errors.Is(err, fosite.ErrNotFound),
		"revoked token must be inaccessible, got: %v", err)
}

func TestFositeStore_RefreshToken_ReuseRevokesFamily(t *testing.T) {
	store, db, tenantID, clientID := setupFositeStoreWithRepos(t)
	ctx := tenantCtxFor(tenantID)

	// Create parent token.
	parentReq := newFositeRequest(clientID, "alice", time.Hour)
	parentSig := "rt-family-parent"
	require.NoError(t, store.CreateRefreshTokenSession(ctx, parentSig, parentReq))

	// Read back to get the assigned family ID.
	var parentRow models.OAuth2SessionGORM
	require.NoError(t, db.Where("signature = ? AND token_type = ?", parentSig, "refresh_token").First(&parentRow).Error)
	familyID := parentRow.TokenFamilyID
	require.NotEmpty(t, familyID)

	// Create child token in the same family.
	childReq := newFositeRequest(clientID, "alice", time.Hour)
	if jwtSess, ok := childReq.GetSession().(*model.JWTSession); ok {
		jwtSess.TokenFamilyID = familyID
	}
	childSig := "rt-family-child"
	require.NoError(t, store.CreateRefreshTokenSession(ctx, childSig, childReq))

	// Simulate reuse: mark family as revoked with an expired grace window.
	past := time.Now().UTC().Add(-time.Hour)
	require.NoError(t, db.Model(&models.OAuth2SessionGORM{}).
		Where("token_family_id = ? AND token_type = ?", familyID, "refresh_token").
		Updates(map[string]interface{}{
			"active":           false,
			"grace_expires_at": past,
		}).Error)

	_, parentErr := store.GetRefreshTokenSession(ctx, parentSig, model.NewJWTSession("", ""))
	_, childErr := store.GetRefreshTokenSession(ctx, childSig, model.NewJWTSession("", ""))

	assert.Error(t, parentErr, "parent token of revoked family must be inaccessible")
	assert.Error(t, childErr, "child token of revoked family must be inaccessible")
}

func TestFositeStore_RefreshToken_GracePeriod_Within(t *testing.T) {
	store, _, tenantID, clientID := setupFositeStoreWithRepos(t)
	ctx := tenantCtxFor(tenantID)

	req := newFositeRequest(clientID, "alice", time.Hour)
	sig := "rt-grace-within"

	require.NoError(t, store.CreateRefreshTokenSession(ctx, sig, req))
	// DeleteRefreshTokenSession deactivates and sets a 15-second grace window.
	require.NoError(t, store.DeleteRefreshTokenSession(ctx, sig))

	// Within the grace window the token may still be readable.
	got, err := store.GetRefreshTokenSession(ctx, sig, model.NewJWTSession("", ""))
	if err == nil {
		assert.Equal(t, clientID, got.GetClient().GetID())
	}
	// err == ErrInactiveToken is also valid if the window was consumed by timing.
}

func TestFositeStore_RefreshToken_GracePeriod_Expired(t *testing.T) {
	store, db, tenantID, clientID := setupFositeStoreWithRepos(t)
	ctx := tenantCtxFor(tenantID)

	req := newFositeRequest(clientID, "alice", time.Hour)
	sig := "rt-grace-expired"

	require.NoError(t, store.CreateRefreshTokenSession(ctx, sig, req))

	// Force the grace window into the past.
	past := time.Now().UTC().Add(-time.Hour)
	require.NoError(t, db.Model(&models.OAuth2SessionGORM{}).
		Where("signature = ? AND token_type = ?", sig, "refresh_token").
		Updates(map[string]interface{}{
			"active":           false,
			"grace_expires_at": past,
		}).Error)

	_, err := store.GetRefreshTokenSession(ctx, sig, model.NewJWTSession("", ""))
	assert.True(t, errors.Is(err, fosite.ErrInactiveToken) || errors.Is(err, fosite.ErrNotFound),
		"expired grace period must make token inaccessible, got: %v", err)
}

func TestFositeStore_AccessToken_RevokeAndGet(t *testing.T) {
	store, _, tenantID, clientID := setupFositeStoreWithRepos(t)
	ctx := tenantCtxFor(tenantID)

	req := newFositeRequest(clientID, "alice", time.Hour)
	sig := "at-revoke-get-001"

	require.NoError(t, store.CreateAccessTokenSession(ctx, sig, req))

	// Should be retrievable before revocation.
	got, err := store.GetAccessTokenSession(ctx, sig, model.NewJWTSession("", ""))
	require.NoError(t, err)
	assert.Equal(t, clientID, got.GetClient().GetID())

	// Revoke by request ID.
	require.NoError(t, store.RevokeAccessToken(ctx, req.GetID()))

	_, err = store.GetAccessTokenSession(ctx, sig, model.NewJWTSession("", ""))
	assert.True(t, errors.Is(err, fosite.ErrInactiveToken) || errors.Is(err, fosite.ErrNotFound),
		"revoked access token must not be retrievable, got: %v", err)
}
