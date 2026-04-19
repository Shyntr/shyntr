package models

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

// TenantBrandingGORM persists one branding row per tenant.
// DraftConfig is always present (JSON string, not null).
// PublishedConfig is nil until the first Publish operation.
// PublishedAt uses sql.NullTime for portable NULL handling across SQLite and PostgreSQL.
type TenantBrandingGORM struct {
	TenantID        string    `gorm:"primaryKey;type:varchar(255)"`
	DraftConfig     string    `gorm:"type:text;not null"`
	PublishedConfig *string   `gorm:"type:text"`
	UpdatedAt       time.Time `gorm:"autoUpdateTime"`
	PublishedAt     sql.NullTime
}

func (TenantBrandingGORM) TableName() string { return "tenant_branding" }

// ToDomain converts the GORM row to a domain TenantBranding aggregate.
func (m *TenantBrandingGORM) ToDomain() (*model.TenantBranding, error) {
	b := &model.TenantBranding{
		TenantID:  m.TenantID,
		UpdatedAt: m.UpdatedAt,
	}
	if m.PublishedAt.Valid {
		t := m.PublishedAt.Time
		b.PublishedAt = &t
	}

	if err := json.Unmarshal([]byte(m.DraftConfig), &b.Draft); err != nil {
		return nil, fmt.Errorf("branding: corrupt draft_config for tenant %s: %w", m.TenantID, err)
	}

	if m.PublishedConfig != nil {
		var pub model.BrandingConfig
		if err := json.Unmarshal([]byte(*m.PublishedConfig), &pub); err != nil {
			return nil, fmt.Errorf("branding: corrupt published_config for tenant %s: %w", m.TenantID, err)
		}
		b.Published = &pub
	}

	return b, nil
}

// FromDomainBranding converts a domain TenantBranding aggregate to a GORM row.
func FromDomainBranding(b *model.TenantBranding) (*TenantBrandingGORM, error) {
	draftJSON, err := json.Marshal(b.Draft)
	if err != nil {
		return nil, fmt.Errorf("branding: failed to marshal draft_config: %w", err)
	}

	m := &TenantBrandingGORM{
		TenantID:    b.TenantID,
		DraftConfig: string(draftJSON),
		UpdatedAt:   b.UpdatedAt,
	}
	if b.PublishedAt != nil {
		m.PublishedAt = sql.NullTime{Time: *b.PublishedAt, Valid: true}
	}

	if b.Published != nil {
		pubJSON, err := json.Marshal(b.Published)
		if err != nil {
			return nil, fmt.Errorf("branding: failed to marshal published_config: %w", err)
		}
		s := string(pubJSON)
		m.PublishedConfig = &s
	}

	return m, nil
}
