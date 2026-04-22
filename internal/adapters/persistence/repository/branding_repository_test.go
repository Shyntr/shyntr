package repository_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/repository"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupBrandingRepoDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), fmt.Sprintf("%s.db", t.Name()))
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.TenantBrandingGORM{}))
	return db
}

func defaultConfig() model.BrandingConfig { return model.DefaultBrandingConfig() }

func TestBrandingRepository_GetReturnsNotExistsWhenAbsent(t *testing.T) {
	t.Parallel()
	db := setupBrandingRepoDB(t)
	repo := repository.NewBrandingRepository(db)
	ctx := context.Background()

	b, exists, err := repo.Get(ctx, "tenant-x")
	require.NoError(t, err)
	assert.False(t, exists)
	assert.Nil(t, b)
}

func TestBrandingRepository_SaveAndGet(t *testing.T) {
	t.Parallel()
	db := setupBrandingRepoDB(t)
	repo := repository.NewBrandingRepository(db)
	ctx := context.Background()

	cfg := defaultConfig()
	cfg.ThemeID = "custom"

	b := &model.TenantBranding{
		TenantID: "tenant-save",
		Draft:    cfg,
	}
	require.NoError(t, repo.Save(ctx, b))

	got, exists, err := repo.Get(ctx, "tenant-save")
	require.NoError(t, err)
	require.True(t, exists)
	assert.Equal(t, "custom", got.Draft.ThemeID)
	assert.Nil(t, got.Published)
}

func TestBrandingRepository_SaveUpserts(t *testing.T) {
	t.Parallel()
	db := setupBrandingRepoDB(t)
	repo := repository.NewBrandingRepository(db)
	ctx := context.Background()

	b := &model.TenantBranding{TenantID: "tenant-upsert", Draft: defaultConfig()}
	require.NoError(t, repo.Save(ctx, b))

	// Second save with different ThemeID must overwrite.
	b.Draft.ThemeID = "overwritten"
	require.NoError(t, repo.Save(ctx, b))

	got, _, err := repo.Get(ctx, "tenant-upsert")
	require.NoError(t, err)
	assert.Equal(t, "overwritten", got.Draft.ThemeID)
}

func TestBrandingRepository_PublishCopiesDraftToPublished(t *testing.T) {
	t.Parallel()
	db := setupBrandingRepoDB(t)
	repo := repository.NewBrandingRepository(db)
	ctx := context.Background()

	cfg := defaultConfig()
	cfg.ThemeID = "to-publish"
	b := &model.TenantBranding{TenantID: "tenant-publish", Draft: cfg}
	require.NoError(t, repo.Save(ctx, b))

	require.NoError(t, repo.Publish(ctx, "tenant-publish"))

	got, _, err := repo.Get(ctx, "tenant-publish")
	require.NoError(t, err)
	require.NotNil(t, got.Published)
	assert.Equal(t, "to-publish", got.Published.ThemeID)
	assert.Equal(t, got.Draft.ThemeID, got.Published.ThemeID)
	assert.NotNil(t, got.PublishedAt)
}

func TestBrandingRepository_PublishReturnsNotFoundWhenAbsent(t *testing.T) {
	t.Parallel()
	db := setupBrandingRepoDB(t)
	repo := repository.NewBrandingRepository(db)
	ctx := context.Background()

	err := repo.Publish(ctx, "non-existent-tenant")
	assert.ErrorIs(t, err, repository.ErrBrandingNotFound)
}

func TestBrandingRepository_TenantIsolation(t *testing.T) {
	t.Parallel()
	db := setupBrandingRepoDB(t)
	repo := repository.NewBrandingRepository(db)
	ctx := context.Background()

	cfgA := defaultConfig()
	cfgA.ThemeID = "theme-a"
	require.NoError(t, repo.Save(ctx, &model.TenantBranding{TenantID: "tenant-a", Draft: cfgA}))

	cfgB := defaultConfig()
	cfgB.ThemeID = "theme-b"
	require.NoError(t, repo.Save(ctx, &model.TenantBranding{TenantID: "tenant-b", Draft: cfgB}))

	gotA, _, err := repo.Get(ctx, "tenant-a")
	require.NoError(t, err)
	assert.Equal(t, "theme-a", gotA.Draft.ThemeID)

	gotB, _, err := repo.Get(ctx, "tenant-b")
	require.NoError(t, err)
	assert.Equal(t, "theme-b", gotB.Draft.ThemeID)

	// Cross-tenant: tenant-a must not see tenant-b's config.
	assert.NotEqual(t, gotA.Draft.ThemeID, gotB.Draft.ThemeID)
}

func TestBrandingRepository_DeleteByTenant(t *testing.T) {
	t.Parallel()
	db := setupBrandingRepoDB(t)
	repo := repository.NewBrandingRepository(db)
	ctx := context.Background()

	require.NoError(t, repo.Save(ctx, &model.TenantBranding{TenantID: "tenant-del", Draft: defaultConfig()}))

	require.NoError(t, repo.DeleteByTenant(ctx, "tenant-del"))

	_, exists, err := repo.Get(ctx, "tenant-del")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestBrandingRepository_DeleteByTenantNoopWhenAbsent(t *testing.T) {
	t.Parallel()
	db := setupBrandingRepoDB(t)
	repo := repository.NewBrandingRepository(db)
	ctx := context.Background()

	require.NoError(t, repo.DeleteByTenant(ctx, "never-existed"))
}

func TestBrandingRepository_SavePreservesPublishedConfig(t *testing.T) {
	t.Parallel()
	db := setupBrandingRepoDB(t)
	repo := repository.NewBrandingRepository(db)
	ctx := context.Background()

	cfg := defaultConfig()
	b := &model.TenantBranding{TenantID: "tenant-preserve", Draft: cfg}
	require.NoError(t, repo.Save(ctx, b))
	require.NoError(t, repo.Publish(ctx, "tenant-preserve"))

	// Now update draft only.
	b2, _, err := repo.Get(ctx, "tenant-preserve")
	require.NoError(t, err)
	b2.Draft.ThemeID = "new-draft"
	require.NoError(t, repo.Save(ctx, b2))

	got, _, err := repo.Get(ctx, "tenant-preserve")
	require.NoError(t, err)
	assert.Equal(t, "new-draft", got.Draft.ThemeID)
	require.NotNil(t, got.Published)
	// Published must still hold the original ThemeID ("default"), not "new-draft".
	assert.Equal(t, "default", got.Published.ThemeID)
}
