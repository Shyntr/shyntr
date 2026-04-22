package payload

import (
	"reflect"
	"time"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

// UpdateBrandingDraftRequest is the body for PUT /tenants/:id/branding/draft.
type UpdateBrandingDraftRequest struct {
	Theme model.BrandingConfig `json:"theme"`
}

// ResetBrandingRequest is the body for POST /tenants/:id/branding/reset.
type ResetBrandingRequest struct {
	Target string `json:"target" binding:"required,oneof=draft draft_and_published"`
}

// BrandingResponse is the unified response for all branding endpoints.
// Published always contains a resolved config (falls back to defaults when never published).
type BrandingResponse struct {
	TenantID              string               `json:"tenantId"`
	Draft                 model.BrandingConfig `json:"draft"`
	Published             model.BrandingConfig `json:"published"`
	HasUnpublishedChanges bool                 `json:"hasUnpublishedChanges"`
	UpdatedAt             *time.Time           `json:"updatedAt"`
	PublishedAt           *time.Time           `json:"publishedAt"`
}

// BrandingResponseFromDomain builds a BrandingResponse from a domain TenantBranding.
// Published falls back to DefaultBrandingConfig() when no publish has occurred.
func BrandingResponseFromDomain(b *model.TenantBranding) BrandingResponse {
	effectivePublished := model.DefaultBrandingConfig()
	if b.Published != nil {
		effectivePublished = *b.Published
	}

	var updatedAt *time.Time
	if !b.UpdatedAt.IsZero() {
		t := b.UpdatedAt
		updatedAt = &t
	}

	return BrandingResponse{
		TenantID:              b.TenantID,
		Draft:                 b.Draft,
		Published:             effectivePublished,
		HasUnpublishedChanges: !reflect.DeepEqual(b.Draft, effectivePublished),
		UpdatedAt:             updatedAt,
		PublishedAt:           b.PublishedAt,
	}
}
