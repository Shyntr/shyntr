package repository

import (
	"context"
	"errors"

	"github.com/nevzatcirak/shyntr/internal/adapters/persistence/models"
	"github.com/nevzatcirak/shyntr/internal/application/port"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
	"gorm.io/gorm"
)

type tenantRepository struct {
	db *gorm.DB
}

func NewTenantRepository(db *gorm.DB) port.TenantRepository {
	return &tenantRepository{db: db}
}

func (r *tenantRepository) Create(ctx context.Context, tenant *entity.Tenant) error {
	dbModel := models.FromDomainTenant(tenant)
	return r.db.WithContext(ctx).Create(dbModel).Error
}

func (r *tenantRepository) GetByID(ctx context.Context, id string) (*entity.Tenant, error) {
	var dbModel models.TenantGORM
	if err := r.db.WithContext(ctx).First(&dbModel, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("tenant not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *tenantRepository) GetCount(ctx context.Context) (int64, error) {
	var dbModel models.TenantGORM
	var count int64
	if err := r.db.WithContext(ctx).Model(&dbModel).Count(&count).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, errors.New("tenant count not found")
		}
		return 0, err
	}
	return count, nil
}

func (r *tenantRepository) GetByName(ctx context.Context, name string) (*entity.Tenant, error) {
	var dbModel models.TenantGORM
	if err := r.db.WithContext(ctx).First(&dbModel, "name = ?", name).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("tenant not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *tenantRepository) Update(ctx context.Context, tenant *entity.Tenant) error {
	dbModel := models.FromDomainTenant(tenant)
	return r.db.WithContext(ctx).Model(&models.TenantGORM{}).Where("id = ?", tenant.ID).Updates(dbModel).Error
}

func (r *tenantRepository) Delete(ctx context.Context, id string) error {
	// Zero Trust: Transactional cascade delete ensures no orphaned data is left behind.
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		tablesToClear := []interface{}{
			&models.OAuth2ClientGORM{},
			// &models.SAMLClientGORM{},
			// &models.OIDCConnectionGORM{},
			// &models.SAMLConnectionGORM{},
		}
		for _, table := range tablesToClear {
			if err := tx.Where("tenant_id = ?", id).Delete(table).Error; err != nil {
				return err
			}
		}
		return tx.Where("id = ?", id).Delete(&models.TenantGORM{}).Error
	})
}

func (r *tenantRepository) List(ctx context.Context) ([]*entity.Tenant, error) {
	var dbModels []models.TenantGORM
	if err := r.db.WithContext(ctx).Find(&dbModels).Error; err != nil {
		return nil, err
	}
	var entities []*entity.Tenant
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}
