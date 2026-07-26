package repository_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/repository"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupOIDCRepoTestDB(t *testing.T) *gorm.DB {
	dbName := fmt.Sprintf("file:oidc_repo_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.OAuth2ClientGORM{})
	require.NoError(t, err)

	return db
}

func TestOAuth2ClientRepository_CreateAndGetByTenant(t *testing.T) {
	t.Parallel()
	db := setupOIDCRepoTestDB(t)
	repo := repository.NewOAuth2ClientRepository(db)
	ctx := context.Background()

	tenantID := "tnt_oidc_01"
	clientID := "client_oidc_123"

	domainClient := &model.OAuth2Client{
		ID:       clientID,
		TenantID: tenantID,
		Public:   true,
	}

	err := repo.Create(ctx, domainClient)
	require.NoError(t, err, "Should create OIDC client successfully")

	fetchedClient, err := repo.GetByTenantAndID(ctx, tenantID, clientID)
	require.NoError(t, err)
	assert.Equal(t, clientID, fetchedClient.ID)
	assert.Equal(t, tenantID, fetchedClient.TenantID)
	assert.True(t, fetchedClient.Public)

	wrongTenantClient, err := repo.GetByTenantAndID(ctx, "tnt_hacker_99", clientID)
	assert.Error(t, err, "Must return error for cross-tenant access")
	assert.Nil(t, wrongTenantClient)
	assert.Equal(t, "oauth2 client not found", err.Error())
}

func TestOAuth2ClientRepository_AttributeMappingRoundTrip(t *testing.T) {
	t.Parallel()
	db := setupOIDCRepoTestDB(t)
	repo := repository.NewOAuth2ClientRepository(db)
	ctx := context.Background()

	tenantID := "tnt_oidc_attr"
	clientID := "client_oidc_attr_123"

	mapping := map[string]model.AttributeMappingRule{
		"email": {Source: "email", Target: "email", Type: "string"},
		"roles": {Source: "groups", Target: "roles", Type: "array", TargetScopes: []string{"roles"}},
	}

	domainClient := &model.OAuth2Client{
		ID:               clientID,
		TenantID:         tenantID,
		Public:           true,
		AttributeMapping: mapping,
	}

	// Create round-trip
	require.NoError(t, repo.Create(ctx, domainClient))

	fetched, err := repo.GetByTenantAndID(ctx, tenantID, clientID)
	require.NoError(t, err)
	assert.Equal(t, mapping, fetched.AttributeMapping, "attribute_mapping must round-trip on create")

	// Update round-trip
	updatedMapping := map[string]model.AttributeMappingRule{
		"department": {Source: "dept", Target: "department", Type: "string"},
	}
	fetched.AttributeMapping = updatedMapping
	require.NoError(t, repo.Update(ctx, fetched))

	refetched, err := repo.GetByTenantAndID(ctx, tenantID, clientID)
	require.NoError(t, err)
	assert.Equal(t, updatedMapping, refetched.AttributeMapping, "attribute_mapping must round-trip on update")
}

func TestOAuth2ClientRepository_PassthroughAndExcludeRoundTrip(t *testing.T) {
	t.Parallel()
	db := setupOIDCRepoTestDB(t)
	repo := repository.NewOAuth2ClientRepository(db)
	ctx := context.Background()

	tenantID := "tnt_oidc_pt"
	clientID := "client_oidc_pt_123"

	domainClient := &model.OAuth2Client{
		ID:                   clientID,
		TenantID:             tenantID,
		Public:               true,
		AttributePassthrough: true,
		AttributeExclude:     []string{"ssn", "internal_id"},
	}

	// Create round-trip: both new storage-only fields persist and read back.
	require.NoError(t, repo.Create(ctx, domainClient))

	fetched, err := repo.GetByTenantAndID(ctx, tenantID, clientID)
	require.NoError(t, err)
	assert.True(t, fetched.AttributePassthrough, "attribute_passthrough must round-trip on create")
	assert.Equal(t, []string{"ssn", "internal_id"}, fetched.AttributeExclude, "attribute_exclude must round-trip on create")

	// Update round-trip: a changed non-empty exclude persists; passthrough stays set.
	fetched.AttributeExclude = []string{"password"}
	require.NoError(t, repo.Update(ctx, fetched))

	refetched, err := repo.GetByTenantAndID(ctx, tenantID, clientID)
	require.NoError(t, err)
	assert.True(t, refetched.AttributePassthrough, "attribute_passthrough must round-trip on update")
	assert.Equal(t, []string{"password"}, refetched.AttributeExclude, "attribute_exclude must round-trip on update")
}

func TestOAuth2ClientRepository_ClientCounts(t *testing.T) {
	t.Parallel()
	db := setupOIDCRepoTestDB(t)
	repo := repository.NewOAuth2ClientRepository(db)
	ctx := context.Background()

	tenantA := "tnt_A"
	tenantB := "tnt_B"

	_ = repo.Create(ctx, &model.OAuth2Client{ID: "c1", TenantID: tenantA, Public: true})
	_ = repo.Create(ctx, &model.OAuth2Client{ID: "c2", TenantID: tenantA, Public: false}) // Confidential
	_ = repo.Create(ctx, &model.OAuth2Client{ID: "c3", TenantID: tenantB, Public: true})

	countA, err := repo.GetClientCount(ctx, tenantA)
	require.NoError(t, err)
	assert.Equal(t, int64(2), countA)

	publicCountA, err := repo.GetPublicClientCount(ctx, tenantA)
	require.NoError(t, err)
	assert.Equal(t, int64(1), publicCountA)

	confCountA, err := repo.GetConfidentialClientCount(ctx, tenantA)
	require.NoError(t, err)
	assert.Equal(t, int64(1), confCountA)

	countB, err := repo.GetClientCount(ctx, tenantB)
	require.NoError(t, err)
	assert.Equal(t, int64(1), countB)
}

func TestOAuth2ClientRepository_DeleteBoundary(t *testing.T) {
	t.Parallel()
	db := setupOIDCRepoTestDB(t)
	repo := repository.NewOAuth2ClientRepository(db)
	ctx := context.Background()

	tenantID := "tnt_oidc_01"
	clientID := "client_oidc_123"

	_ = repo.Create(ctx, &model.OAuth2Client{ID: clientID, TenantID: tenantID})

	err := repo.Delete(ctx, "tnt_wrong", clientID)
	assert.Error(t, err, "Cross-tenant deletion must fail")

	err = repo.Delete(ctx, tenantID, clientID)
	assert.NoError(t, err, "Correct tenant deletion must succeed")

	_, err = repo.GetByTenantAndID(ctx, tenantID, clientID)
	assert.Error(t, err)
}

func TestOAuth2ClientRepository_UpdateRespectsTenantBoundary(t *testing.T) {
	t.Parallel()
	db := setupOIDCRepoTestDB(t)
	repo := repository.NewOAuth2ClientRepository(db)
	ctx := context.Background()

	client := &model.OAuth2Client{
		ID:                      "client_oidc_123",
		TenantID:                "tenant-a",
		Name:                    "Tenant A Client",
		Public:                  true,
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ResponseModes:           []string{"query"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "none",
		EnforcePKCE:             true,
		SubjectType:             "public",
	}
	require.NoError(t, repo.Create(ctx, client))

	crossTenant := &model.OAuth2Client{
		ID:                      client.ID,
		TenantID:                "tenant-b",
		Name:                    "Hacked",
		Public:                  true,
		RedirectURIs:            client.RedirectURIs,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		ResponseModes:           client.ResponseModes,
		Scopes:                  client.Scopes,
		TokenEndpointAuthMethod: "none",
		EnforcePKCE:             true,
		SubjectType:             "public",
	}
	err := repo.Update(ctx, crossTenant)
	require.Error(t, err)
	assert.Equal(t, "oauth2 client not found", err.Error())

	fetched, err := repo.GetByTenantAndID(ctx, "tenant-a", client.ID)
	require.NoError(t, err)
	assert.Equal(t, "Tenant A Client", fetched.Name)
}
