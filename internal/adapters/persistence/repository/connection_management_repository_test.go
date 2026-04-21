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

func setupOIDCConnectionRepoTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbName := fmt.Sprintf("file:oidc_conn_repo_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.OIDCConnectionGORM{}))
	return db
}

func setupSAMLConnectionRepoTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbName := fmt.Sprintf("file:saml_conn_repo_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SAMLConnectionGORM{}))
	return db
}

func TestOIDCConnectionRepository_UpdateRespectsTenantBoundary(t *testing.T) {
	t.Parallel()
	db := setupOIDCConnectionRepoTestDB(t)
	repo := repository.NewOIDCConnectionRepository(db)
	ctx := context.Background()

	conn := &model.OIDCConnection{
		ID:        "oidc-conn-a",
		TenantID:  "tenant-a",
		Name:      "Tenant A OIDC",
		IssuerURL: "https://issuer.example.com",
		ClientID:  "client-a",
	}
	require.NoError(t, repo.Create(ctx, conn))

	crossTenant := &model.OIDCConnection{
		ID:        conn.ID,
		TenantID:  "tenant-b",
		Name:      "Hacked",
		IssuerURL: conn.IssuerURL,
		ClientID:  conn.ClientID,
	}
	err := repo.Update(ctx, crossTenant)
	require.Error(t, err)
	assert.Equal(t, "oidc connection not found", err.Error())

	fetched, err := repo.GetByTenantAndID(ctx, "tenant-a", conn.ID)
	require.NoError(t, err)
	assert.Equal(t, "Tenant A OIDC", fetched.Name)
}

func TestSAMLConnectionRepository_UpdateRespectsTenantBoundary(t *testing.T) {
	t.Parallel()
	db := setupSAMLConnectionRepoTestDB(t)
	repo := repository.NewSAMLConnectionRepository(db)
	ctx := context.Background()

	conn := &model.SAMLConnection{
		ID:              "saml-conn-a",
		TenantID:        "tenant-a",
		Name:            "Tenant A SAML",
		IdpEntityID:     "https://idp.example.com/metadata",
		IdpSingleSignOn: "https://idp.example.com/sso",
		IdpCertificate:  "MIIDFAKECERT",
	}
	require.NoError(t, repo.Create(ctx, conn))

	crossTenant := &model.SAMLConnection{
		ID:              conn.ID,
		TenantID:        "tenant-b",
		Name:            "Hacked",
		IdpEntityID:     conn.IdpEntityID,
		IdpSingleSignOn: conn.IdpSingleSignOn,
		IdpCertificate:  conn.IdpCertificate,
	}
	err := repo.Update(ctx, crossTenant)
	require.Error(t, err)
	assert.Equal(t, "saml connection not found", err.Error())

	fetched, err := repo.GetByTenantAndID(ctx, "tenant-a", conn.ID)
	require.NoError(t, err)
	assert.Equal(t, "Tenant A SAML", fetched.Name)
}
