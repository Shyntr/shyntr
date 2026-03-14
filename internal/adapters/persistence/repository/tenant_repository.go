package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"gorm.io/gorm"
)

type tenantRepository struct {
	db *gorm.DB
}

func NewTenantRepository(db *gorm.DB) port.TenantRepository {
	return &tenantRepository{db: db}
}

func (r *tenantRepository) Create(ctx context.Context, tenant *model.Tenant) error {
	dbModel := models.FromDomainTenant(tenant)
	return r.db.WithContext(ctx).Create(dbModel).Error
}

func (r *tenantRepository) GetByID(ctx context.Context, id string) (*model.Tenant, error) {
	var dbModel models.TenantGORM
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("tenant not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *tenantRepository) GetByName(ctx context.Context, name string) (*model.Tenant, error) {
	var dbModel models.TenantGORM
	if err := r.db.WithContext(ctx).Where("name = ?", name).First(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("tenant not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *tenantRepository) GetCount(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&models.TenantGORM{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}
func (r *tenantRepository) Update(ctx context.Context, tenant *model.Tenant) error {
	dbModel := models.FromDomainTenant(tenant)
	return r.db.WithContext(ctx).Model(&models.TenantGORM{}).Where("id = ?", tenant.ID).Updates(dbModel).Error
}

func (r *tenantRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Where("id = ?", id).Delete(&models.TenantGORM{}).Error
}

// CascadeDelete: GORM bağımlılığı ve iş mantığı (Transaction) handler'dan buraya taşındı.
func (r *tenantRepository) CascadeDelete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("tenant_id = ?", id).Delete(&models.OAuth2ClientGORM{}).Error; err != nil {
			return fmt.Errorf("failed to delete oidc clients: %w", err)
		}
		if err := tx.Where("tenant_id = ?", id).Delete(&models.SAMLClientGORM{}).Error; err != nil {
			return fmt.Errorf("failed to delete saml clients: %w", err)
		}
		if err := tx.Where("tenant_id = ?", id).Delete(&models.OIDCConnectionGORM{}).Error; err != nil {
			return fmt.Errorf("failed to delete oidc connections: %w", err)
		}
		if err := tx.Where("tenant_id = ?", id).Delete(&models.SAMLConnectionGORM{}).Error; err != nil {
			return fmt.Errorf("failed to delete saml connections: %w", err)
		}
		if err := tx.Where("tenant_id = ?", id).Delete(&models.LoginRequestGORM{}).Error; err != nil {
			return fmt.Errorf("failed to delete login requests: %w", err)
		}
		if err := tx.Where("id = ?", id).Delete(&models.TenantGORM{}).Error; err != nil {
			return fmt.Errorf("failed to delete tenant: %w", err)
		}
		return nil
	})
}

func (r *tenantRepository) List(ctx context.Context) ([]*model.Tenant, error) {
	var dbModels []models.TenantGORM
	if err := r.db.WithContext(ctx).Find(&dbModels).Error; err != nil {
		return nil, err
	}
	entities := make([]*model.Tenant, 0)
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}
