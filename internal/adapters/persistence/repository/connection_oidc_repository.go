package repository

import (
	"context"
	"errors"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"gorm.io/gorm"
)

type oidcConnectionRepository struct {
	db *gorm.DB
}

func NewOIDCConnectionRepository(db *gorm.DB) port.OIDCConnectionRepository {
	return &oidcConnectionRepository{db: db}
}

func (r *oidcConnectionRepository) Create(ctx context.Context, conn *model.OIDCConnection) error {
	dbModel := models.FromDomainOIDCConnection(conn)
	return r.db.WithContext(ctx).Create(dbModel).Error
}

func (r *oidcConnectionRepository) GetByID(ctx context.Context, id string) (*model.OIDCConnection, error) {
	var dbModel models.OIDCConnectionGORM
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("oidc connection not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *oidcConnectionRepository) GetByTenantAndID(ctx context.Context, tenantID, id string) (*model.OIDCConnection, error) {
	var dbModel models.OIDCConnectionGORM
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).First(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("oidc connection not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *oidcConnectionRepository) GetConnectionCount(ctx context.Context, tenantID string) (int64, error) {
	var count int64
	query := r.db.WithContext(ctx).Model(&models.OIDCConnectionGORM{})
	if tenantID != "" {
		query = query.Where("tenant_id = ?", tenantID)
	}
	if err := query.Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}
func (r *oidcConnectionRepository) Update(ctx context.Context, conn *model.OIDCConnection) error {
	dbModel := models.FromDomainOIDCConnection(conn)
	return r.db.WithContext(ctx).Model(&models.OIDCConnectionGORM{}).
		Where("tenant_id = ? AND id = ?", conn.TenantID, conn.ID).
		Updates(dbModel).Error
}

func (r *oidcConnectionRepository) Delete(ctx context.Context, tenantID, id string) error {
	result := r.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).Delete(&models.OIDCConnectionGORM{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("connection not found or already deleted")
	}
	return nil
}

func (r *oidcConnectionRepository) ListByTenant(ctx context.Context, tenantID string) ([]*model.OIDCConnection, error) {
	var dbModels []models.OIDCConnectionGORM
	query := r.db.WithContext(ctx).Model(&models.OIDCConnectionGORM{})

	if tenantID != "" {
		query = query.Where("tenant_id = ?", tenantID)
	}

	if err := query.Find(&dbModels).Error; err != nil {
		return nil, err
	}
	entities := make([]*model.OIDCConnection, 0)
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}

func (r *oidcConnectionRepository) ListActiveByTenant(ctx context.Context, tenantID string) ([]*model.OIDCConnection, error) {
	var dbModels []models.OIDCConnectionGORM
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND active = ?", tenantID, true).Find(&dbModels).Error; err != nil {
		return nil, err
	}
	var entities []*model.OIDCConnection
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}

func (r *oidcConnectionRepository) List(ctx context.Context) ([]*model.OIDCConnection, error) {
	var dbModels []models.OIDCConnectionGORM
	if err := r.db.WithContext(ctx).Find(&dbModels).Error; err != nil {
		return nil, err
	}
	entities := make([]*model.OIDCConnection, 0)
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}
