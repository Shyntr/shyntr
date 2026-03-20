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

func setupSAMLRepoTestDB(t *testing.T) *gorm.DB {
	dbName := fmt.Sprintf("file:saml_repo_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.SAMLClientGORM{})
	require.NoError(t, err)

	return db
}

func TestSAMLClientRepository_CreateAndGetByID(t *testing.T) {
	t.Parallel()
	db := setupSAMLRepoTestDB(t)
	repo := repository.NewSAMLClientRepository(db)
	ctx := context.Background()

	tenantID := "tnt_saml_01"
	clientID := "client_saml_123"

	domainClient := &model.SAMLClient{
		ID:       clientID,
		TenantID: tenantID,
		EntityID: "https://sp.example.com/saml",
	}

	err := repo.Create(ctx, domainClient)
	require.NoError(t, err, "Should create SAML client successfully")

	fetchedClient, err := repo.GetByID(ctx, tenantID, clientID)
	require.NoError(t, err)
	assert.Equal(t, clientID, fetchedClient.ID)
	assert.Equal(t, "https://sp.example.com/saml", fetchedClient.EntityID)

	wrongTenantClient, err := repo.GetByID(ctx, "tnt_hacker_99", clientID)
	assert.Error(t, err, "Cross-tenant access must be blocked")
	assert.Nil(t, wrongTenantClient)
	assert.Equal(t, "saml client not found", err.Error())
}

func TestSAMLClientRepository_GetByTenantAndEntityID(t *testing.T) {
	t.Parallel()
	db := setupSAMLRepoTestDB(t)
	repo := repository.NewSAMLClientRepository(db)
	ctx := context.Background()

	tenantA := "tnt_saml_A"
	tenantB := "tnt_saml_B"
	entityID := "https://shared-sp.example.com/saml"

	_ = repo.Create(ctx, &model.SAMLClient{ID: "c1", TenantID: tenantA, EntityID: entityID})
	_ = repo.Create(ctx, &model.SAMLClient{ID: "c2", TenantID: tenantB, EntityID: entityID})

	clientA, err := repo.GetByTenantAndEntityID(ctx, tenantA, entityID)
	require.NoError(t, err)
	assert.Equal(t, "c1", clientA.ID)

	clientB, err := repo.GetByTenantAndEntityID(ctx, tenantB, entityID)
	require.NoError(t, err)
	assert.Equal(t, "c2", clientB.ID)
}

func TestSAMLClientRepository_ListByTenant(t *testing.T) {
	t.Parallel()
	db := setupSAMLRepoTestDB(t)
	repo := repository.NewSAMLClientRepository(db)
	ctx := context.Background()

	tenantID := "tnt_saml_list"

	_ = repo.Create(ctx, &model.SAMLClient{ID: "s1", TenantID: tenantID})
	_ = repo.Create(ctx, &model.SAMLClient{ID: "s2", TenantID: tenantID})
	_ = repo.Create(ctx, &model.SAMLClient{ID: "s3", TenantID: "other_tenant"})

	clients, err := repo.ListByTenant(ctx, tenantID)
	require.NoError(t, err)
	assert.Len(t, clients, 2, "Must return only the clients belonging to the specified tenant")
}
