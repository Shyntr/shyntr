package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrBrandingNotFound is returned by Publish when no branding row exists for the tenant.
var ErrBrandingNotFound = errors.New("branding not found")

type brandingRepository struct {
	db *gorm.DB
}

// NewBrandingRepository creates a new BrandingRepository backed by the given *gorm.DB.
func NewBrandingRepository(db *gorm.DB) port.BrandingRepository {
	return &brandingRepository{db: db}
}

// Get returns the branding row for the tenant. Returns (nil, false, nil) when absent.
// Find with Limit(1) is used instead of First so that a missing row is not logged
// as a GORM "record not found" error — absence is a valid business case here.
func (r *brandingRepository) Get(ctx context.Context, tenantID string) (*model.TenantBranding, bool, error) {
	var rows []models.TenantBrandingGORM
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Limit(1).Find(&rows).Error; err != nil {
		return nil, false, err
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	b, err := rows[0].ToDomain()
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// Save upserts the branding row. On primary key conflict, all mutable columns are replaced.
func (r *brandingRepository) Save(ctx context.Context, b *model.TenantBranding) error {
	m, err := models.FromDomainBranding(b)
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"draft_config", "published_config", "published_at", "updated_at"}),
		}).
		Create(m).Error
}

// Publish atomically copies draft_config → published_config for the tenant row.
func (r *brandingRepository) Publish(ctx context.Context, tenantID string) error {
	now := time.Now().UTC()
	result := r.db.WithContext(ctx).
		Model(&models.TenantBrandingGORM{}).
		Where("tenant_id = ?", tenantID).
		Updates(map[string]interface{}{
			"published_config": gorm.Expr("draft_config"),
			"published_at":     sql.NullTime{Time: now, Valid: true},
			"updated_at":       now,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrBrandingNotFound
	}
	return nil
}

// DeleteByTenant permanently deletes the branding row for the tenant. No-op if absent.
func (r *brandingRepository) DeleteByTenant(ctx context.Context, tenantID string) error {
	return r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Delete(&models.TenantBrandingGORM{}).Error
}
