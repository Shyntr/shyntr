package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

// BrandingRepository manages tenant-scoped branding persistence.
// Every method requires a non-empty tenantID — no cross-tenant reads are possible.
type BrandingRepository interface {
	// Get returns the branding row for the tenant.
	// Returns (nil, false, nil) when no row exists.
	Get(ctx context.Context, tenantID string) (*model.TenantBranding, bool, error)

	// Save upserts the branding row.
	// Creates a new row if none exists; overwrites draft_config and published_config otherwise.
	Save(ctx context.Context, b *model.TenantBranding) error

	// Publish atomically copies draft_config into published_config for the tenant row.
	// Returns ErrBrandingNotFound if no row exists.
	Publish(ctx context.Context, tenantID string) error

	// DeleteByTenant permanently deletes the branding row for the tenant.
	// No-op (no error) if no row exists. Called from tenant CascadeDelete.
	DeleteByTenant(ctx context.Context, tenantID string) error
}
