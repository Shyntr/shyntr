package repository

import (
	"context"

	"github.com/nevzatcirak/shyntr/internal/adapters/persistence/models"
	"github.com/nevzatcirak/shyntr/internal/application/port"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
	"gorm.io/gorm"
)

type scopeRepository struct {
	db *gorm.DB
}

func NewScopeRepository(db *gorm.DB) port.ScopeRepository {
	return &scopeRepository{db: db}
}

func (r *scopeRepository) Create(ctx context.Context, scope *entity.Scope) error {
	model := models.FromDomainScope(scope)
	return r.db.WithContext(ctx).Create(model).Error
}

func (r *scopeRepository) GetByID(ctx context.Context, tenantID, id string) (*entity.Scope, error) {
	var model models.ScopeGORM
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).First(&model).Error; err != nil {
		return nil, err
	}
	return model.ToDomain(), nil
}

func (r *scopeRepository) GetByName(ctx context.Context, tenantID, name string) (*entity.Scope, error) {
	var model models.ScopeGORM
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND name = ?", tenantID, name).First(&model).Error; err != nil {
		return nil, err
	}
	return model.ToDomain(), nil
}

func (r *scopeRepository) ListByTenant(ctx context.Context, tenantID string) ([]*entity.Scope, error) {
	var modelsList []models.ScopeGORM
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Find(&modelsList).Error; err != nil {
		return nil, err
	}

	scopes := make([]*entity.Scope, 0, len(modelsList))
	for _, m := range modelsList {
		scopes = append(scopes, m.ToDomain())
	}
	return scopes, nil
}

func (r *scopeRepository) Update(ctx context.Context, scope *entity.Scope) error {
	model := models.FromDomainScope(scope)
	return r.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", scope.TenantID, scope.ID).Updates(model).Error
}

func (r *scopeRepository) Delete(ctx context.Context, tenantID, id string) error {
	return r.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).Delete(&models.ScopeGORM{}).Error
}
