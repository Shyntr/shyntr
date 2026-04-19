package usecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── stub repository ──────────────────────────────────────────────────────────

type stubBrandingRepo struct {
	row    *model.TenantBranding
	exists bool
	err    error

	publishErr  error
	publishedAt *time.Time
}

func (r *stubBrandingRepo) Get(_ context.Context, _ string) (*model.TenantBranding, bool, error) {
	if r.err != nil {
		return nil, false, r.err
	}
	return r.row, r.exists, nil
}

func (r *stubBrandingRepo) Save(_ context.Context, b *model.TenantBranding) error {
	if r.err != nil {
		return r.err
	}
	cp := *b
	r.row = &cp
	r.exists = true
	return nil
}

func (r *stubBrandingRepo) Publish(_ context.Context, _ string) error {
	if r.publishErr != nil {
		return r.publishErr
	}
	if r.row == nil {
		return errors.New("branding not found")
	}
	pub := r.row.Draft
	r.row.Published = &pub
	now := time.Now().UTC()
	r.row.PublishedAt = &now
	r.publishedAt = r.row.PublishedAt
	return nil
}

func (r *stubBrandingRepo) DeleteByTenant(_ context.Context, _ string) error { return nil }

// ─── helpers ─────────────────────────────────────────────────────────────────

func validConfig() model.BrandingConfig { return model.DefaultBrandingConfig() }

func configWithTheme(id string) model.BrandingConfig {
	c := model.DefaultBrandingConfig()
	c.ThemeID = id
	return c
}

// ─── GetBranding ─────────────────────────────────────────────────────────────

func TestBrandingUseCase_GetBranding_ReturnsDefaultsWhenNoRow(t *testing.T) {
	repo := &stubBrandingRepo{}
	uc := usecase.NewBrandingUseCase(repo)

	b, err := uc.GetBranding(context.Background(), "tenant-x")
	require.NoError(t, err)
	assert.Equal(t, model.DefaultBrandingConfig(), b.Draft)
	assert.Nil(t, b.Published)
}

func TestBrandingUseCase_GetBranding_ReturnsStoredRow(t *testing.T) {
	cfg := configWithTheme("stored")
	repo := &stubBrandingRepo{
		row:    &model.TenantBranding{TenantID: "t1", Draft: cfg},
		exists: true,
	}
	uc := usecase.NewBrandingUseCase(repo)

	b, err := uc.GetBranding(context.Background(), "t1")
	require.NoError(t, err)
	assert.Equal(t, "stored", b.Draft.ThemeID)
}

// ─── UpdateDraft ─────────────────────────────────────────────────────────────

func TestBrandingUseCase_UpdateDraft_ValidConfig(t *testing.T) {
	repo := &stubBrandingRepo{}
	uc := usecase.NewBrandingUseCase(repo)

	cfg := configWithTheme("new-theme")
	b, err := uc.UpdateDraft(context.Background(), "t1", cfg)
	require.NoError(t, err)
	assert.Equal(t, "new-theme", b.Draft.ThemeID)
	require.True(t, repo.exists)
}

func TestBrandingUseCase_UpdateDraft_RejectsInvalidConfig(t *testing.T) {
	repo := &stubBrandingRepo{}
	uc := usecase.NewBrandingUseCase(repo)

	bad := model.BrandingConfig{ThemeID: ""} // empty ThemeID is invalid
	_, err := uc.UpdateDraft(context.Background(), "t1", bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "themeId")
	assert.False(t, repo.exists, "Save must not be called when validation fails")
}

func TestBrandingUseCase_UpdateDraft_RejectsInsecureURL(t *testing.T) {
	repo := &stubBrandingRepo{}
	uc := usecase.NewBrandingUseCase(repo)

	cfg := validConfig()
	cfg.Widget.LogoURL = "http://example.com/logo.png" // http not allowed
	_, err := uc.UpdateDraft(context.Background(), "t1", cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

func TestBrandingUseCase_UpdateDraft_AllowsEmptyURL(t *testing.T) {
	repo := &stubBrandingRepo{}
	uc := usecase.NewBrandingUseCase(repo)

	cfg := validConfig()
	cfg.Widget.LogoURL = ""
	_, err := uc.UpdateDraft(context.Background(), "t1", cfg)
	require.NoError(t, err)
}

// ─── Publish ─────────────────────────────────────────────────────────────────

func TestBrandingUseCase_Publish_CopiesDraftToPublished(t *testing.T) {
	cfg := configWithTheme("to-publish")
	repo := &stubBrandingRepo{
		row:    &model.TenantBranding{TenantID: "t1", Draft: cfg},
		exists: true,
	}
	uc := usecase.NewBrandingUseCase(repo)

	b, err := uc.Publish(context.Background(), "t1")
	require.NoError(t, err)
	require.NotNil(t, b.Published)
	assert.Equal(t, "to-publish", b.Published.ThemeID)
}

func TestBrandingUseCase_Publish_WhenNoRowSeedsDefaultsThenPublishes(t *testing.T) {
	repo := &stubBrandingRepo{}
	uc := usecase.NewBrandingUseCase(repo)

	b, err := uc.Publish(context.Background(), "t1")
	require.NoError(t, err)
	require.NotNil(t, b.Published)
	assert.Equal(t, model.DefaultBrandingConfig().ThemeID, b.Published.ThemeID)
}

// ─── Discard ─────────────────────────────────────────────────────────────────

func TestBrandingUseCase_Discard_WhenNeverPublished_ResetsToDefaults(t *testing.T) {
	cfg := configWithTheme("modified")
	repo := &stubBrandingRepo{
		row:    &model.TenantBranding{TenantID: "t1", Draft: cfg},
		exists: true,
	}
	uc := usecase.NewBrandingUseCase(repo)

	b, err := uc.Discard(context.Background(), "t1")
	require.NoError(t, err)
	assert.Equal(t, model.DefaultBrandingConfig().ThemeID, b.Draft.ThemeID)
}

func TestBrandingUseCase_Discard_WhenPublished_RestoresPublished(t *testing.T) {
	pub := configWithTheme("published")
	draft := configWithTheme("newer-draft")
	repo := &stubBrandingRepo{
		row:    &model.TenantBranding{TenantID: "t1", Draft: draft, Published: &pub},
		exists: true,
	}
	uc := usecase.NewBrandingUseCase(repo)

	b, err := uc.Discard(context.Background(), "t1")
	require.NoError(t, err)
	assert.Equal(t, "published", b.Draft.ThemeID)
}

func TestBrandingUseCase_Discard_WhenNoRow_ReturnsDefaultsWithoutPersisting(t *testing.T) {
	repo := &stubBrandingRepo{}
	uc := usecase.NewBrandingUseCase(repo)

	b, err := uc.Discard(context.Background(), "t1")
	require.NoError(t, err)
	assert.Equal(t, model.DefaultBrandingConfig(), b.Draft)
	assert.False(t, repo.exists, "no row should be created on discard when nothing exists")
}

// ─── Reset ────────────────────────────────────────────────────────────────────

func TestBrandingUseCase_Reset_Draft_ResetsOnlyDraft(t *testing.T) {
	pub := configWithTheme("published")
	draft := configWithTheme("custom-draft")
	repo := &stubBrandingRepo{
		row:    &model.TenantBranding{TenantID: "t1", Draft: draft, Published: &pub},
		exists: true,
	}
	uc := usecase.NewBrandingUseCase(repo)

	b, err := uc.Reset(context.Background(), "t1", "draft")
	require.NoError(t, err)
	assert.Equal(t, model.DefaultBrandingConfig().ThemeID, b.Draft.ThemeID)
	require.NotNil(t, b.Published, "published must be unchanged")
	assert.Equal(t, "published", b.Published.ThemeID)
}

func TestBrandingUseCase_Reset_DraftAndPublished_ClearsPublished(t *testing.T) {
	pub := configWithTheme("published")
	repo := &stubBrandingRepo{
		row:    &model.TenantBranding{TenantID: "t1", Draft: pub, Published: &pub},
		exists: true,
	}
	uc := usecase.NewBrandingUseCase(repo)

	b, err := uc.Reset(context.Background(), "t1", "draft_and_published")
	require.NoError(t, err)
	assert.Equal(t, model.DefaultBrandingConfig().ThemeID, b.Draft.ThemeID)
	assert.Nil(t, b.Published)
	assert.Nil(t, b.PublishedAt)
}

func TestBrandingUseCase_Reset_InvalidTarget(t *testing.T) {
	repo := &stubBrandingRepo{}
	uc := usecase.NewBrandingUseCase(repo)

	_, err := uc.Reset(context.Background(), "t1", "invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "target")
}

// ─── HasUnpublishedChanges ────────────────────────────────────────────────────

func TestHasUnpublishedChanges_FalseWhenDraftMatchesDefaults(t *testing.T) {
	b := &model.TenantBranding{TenantID: "t1", Draft: model.DefaultBrandingConfig()}
	assert.False(t, usecase.HasUnpublishedChanges(b))
}

func TestHasUnpublishedChanges_TrueWhenDraftDiffersFromDefaults(t *testing.T) {
	b := &model.TenantBranding{TenantID: "t1", Draft: configWithTheme("custom")}
	assert.True(t, usecase.HasUnpublishedChanges(b))
}

func TestHasUnpublishedChanges_FalseWhenDraftMatchesPublished(t *testing.T) {
	pub := configWithTheme("same")
	b := &model.TenantBranding{TenantID: "t1", Draft: configWithTheme("same"), Published: &pub}
	assert.False(t, usecase.HasUnpublishedChanges(b))
}

func TestHasUnpublishedChanges_TrueWhenDraftDiffersFromPublished(t *testing.T) {
	pub := configWithTheme("old")
	b := &model.TenantBranding{TenantID: "t1", Draft: configWithTheme("new"), Published: &pub}
	assert.True(t, usecase.HasUnpublishedChanges(b))
}
