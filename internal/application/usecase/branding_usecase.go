package usecase

import (
	"context"
	"errors"
	"reflect"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
)

// BrandingUseCase manages the draft/published branding lifecycle for a tenant.
type BrandingUseCase interface {
	GetBranding(ctx context.Context, tenantID string) (*model.TenantBranding, error)
	UpdateDraft(ctx context.Context, tenantID string, config model.BrandingConfig) (*model.TenantBranding, error)
	Publish(ctx context.Context, tenantID string) (*model.TenantBranding, error)
	Discard(ctx context.Context, tenantID string) (*model.TenantBranding, error)
	Reset(ctx context.Context, tenantID string, target string) (*model.TenantBranding, error)
}

type brandingUseCase struct {
	repo port.BrandingRepository
}

// NewBrandingUseCase returns a new BrandingUseCase.
func NewBrandingUseCase(repo port.BrandingRepository) BrandingUseCase {
	return &brandingUseCase{repo: repo}
}

// GetBranding returns the current branding state. If no row exists, defaults are returned
// without persisting a row.
func (u *brandingUseCase) GetBranding(ctx context.Context, tenantID string) (*model.TenantBranding, error) {
	b, exists, err := u.repo.Get(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !exists {
		def := model.DefaultBrandingConfig()
		return &model.TenantBranding{
			TenantID: tenantID,
			Draft:    def,
		}, nil
	}
	return b, nil
}

// UpdateDraft validates and persists the new draft config. Creates the row on first call.
func (u *brandingUseCase) UpdateDraft(ctx context.Context, tenantID string, config model.BrandingConfig) (*model.TenantBranding, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	b, exists, err := u.repo.Get(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !exists {
		b = &model.TenantBranding{TenantID: tenantID}
	}

	b.Draft = config
	if err := u.repo.Save(ctx, b); err != nil {
		return nil, err
	}
	return b, nil
}

// Publish atomically copies draft → published. If no row exists, defaults are persisted first.
func (u *brandingUseCase) Publish(ctx context.Context, tenantID string) (*model.TenantBranding, error) {
	_, exists, err := u.repo.Get(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !exists {
		// No draft row yet — seed with defaults so Publish has a row to operate on.
		def := model.DefaultBrandingConfig()
		seed := &model.TenantBranding{TenantID: tenantID, Draft: def}
		if err := u.repo.Save(ctx, seed); err != nil {
			return nil, err
		}
	}

	if err := u.repo.Publish(ctx, tenantID); err != nil {
		return nil, err
	}

	b, _, err := u.repo.Get(ctx, tenantID)
	return b, err
}

// Discard resets draft to the published state.
// If published is nil (never published), draft is reset to defaults.
// If no row exists at all, a defaults-only TenantBranding is returned without persisting.
func (u *brandingUseCase) Discard(ctx context.Context, tenantID string) (*model.TenantBranding, error) {
	b, exists, err := u.repo.Get(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	def := model.DefaultBrandingConfig()

	if !exists {
		return &model.TenantBranding{TenantID: tenantID, Draft: def}, nil
	}

	if b.Published == nil {
		b.Draft = def
	} else {
		b.Draft = *b.Published
	}

	if err := u.repo.Save(ctx, b); err != nil {
		return nil, err
	}
	return b, nil
}

// Reset sets the draft (and optionally published) back to system defaults.
// target must be "draft" or "draft_and_published".
func (u *brandingUseCase) Reset(ctx context.Context, tenantID string, target string) (*model.TenantBranding, error) {
	if target != "draft" && target != "draft_and_published" {
		return nil, errors.New("target must be 'draft' or 'draft_and_published'")
	}

	def := model.DefaultBrandingConfig()

	b, exists, err := u.repo.Get(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !exists {
		b = &model.TenantBranding{TenantID: tenantID, Draft: def}
	} else {
		b.Draft = def
		if target == "draft_and_published" {
			b.Published = nil
			b.PublishedAt = nil
		}
	}

	if err := u.repo.Save(ctx, b); err != nil {
		return nil, err
	}
	return b, nil
}

// HasUnpublishedChanges returns true when draft differs from the effective published state.
// If Published is nil, the effective published state is the system defaults.
func HasUnpublishedChanges(b *model.TenantBranding) bool {
	if b.Published == nil {
		def := model.DefaultBrandingConfig()
		return !reflect.DeepEqual(b.Draft, def)
	}
	return !reflect.DeepEqual(b.Draft, *b.Published)
}
