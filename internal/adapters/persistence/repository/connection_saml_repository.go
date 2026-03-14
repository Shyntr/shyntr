package repository

import (
	"context"
	"errors"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"gorm.io/gorm"
)

type samlConnectionRepository struct {
	db *gorm.DB
}

func NewSAMLConnectionRepository(db *gorm.DB) port.SAMLConnectionRepository {
	return &samlConnectionRepository{db: db}
}

func (r *samlConnectionRepository) Create(ctx context.Context, conn *model.SAMLConnection) error {
	dbModel := models.FromDomainSAMLConnection(conn)
	return r.db.WithContext(ctx).Create(dbModel).Error
}

func (r *samlConnectionRepository) GetByID(ctx context.Context, id string) (*model.SAMLConnection, error) {
	var dbModel models.SAMLConnectionGORM
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("saml connection not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *samlConnectionRepository) GetByTenantAndID(ctx context.Context, tenantID, id string) (*model.SAMLConnection, error) {
	var dbModel models.SAMLConnectionGORM
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).First(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("saml connection not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *samlConnectionRepository) GetConnectionCount(ctx context.Context, tenantID string) (int64, error) {
	var count int64
	query := r.db.WithContext(ctx).Model(&models.SAMLConnectionGORM{})
	if tenantID != "" {
		query = query.Where("tenant_id = ?", tenantID)
	}
	if err := query.Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *samlConnectionRepository) GetConnectionByIdpEntity(ctx context.Context, tenantID, idpEntity string) (*model.SAMLConnection, error) {
	var dbModel models.SAMLConnectionGORM
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND idp_entity_id = ?", tenantID, idpEntity).First(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("saml connection not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *samlConnectionRepository) Update(ctx context.Context, conn *model.SAMLConnection) error {
	dbModel := models.FromDomainSAMLConnection(conn)
	return r.db.WithContext(ctx).Model(&models.SAMLConnectionGORM{}).
		Where("tenant_id = ? AND id = ?", conn.TenantID, conn.ID).
		Updates(dbModel).Error
}

func (r *samlConnectionRepository) Delete(ctx context.Context, tenantID, id string) error {
	result := r.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).Delete(&models.SAMLConnectionGORM{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("saml connection not found or already deleted")
	}
	return nil
}

func (r *samlConnectionRepository) ListByTenant(ctx context.Context, tenantID string) ([]*model.SAMLConnection, error) {
	var dbModels []models.SAMLConnectionGORM
	query := r.db.WithContext(ctx).Model(&models.SAMLConnectionGORM{})

	if tenantID != "" {
		query = query.Where("tenant_id = ?", tenantID)
	}

	if err := query.Find(&dbModels).Error; err != nil {
		return nil, err
	}
	entities := make([]*model.SAMLConnection, 0)
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}

func (r *samlConnectionRepository) ListActiveByTenant(ctx context.Context, tenantID string) ([]*model.SAMLConnection, error) {
	var dbModels []models.SAMLConnectionGORM
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND active = ?", tenantID, true).Find(&dbModels).Error; err != nil {
		return nil, err
	}
	var entities []*model.SAMLConnection
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}

func (r *samlConnectionRepository) List(ctx context.Context) ([]*model.SAMLConnection, error) {
	var dbModels []models.SAMLConnectionGORM
	if err := r.db.WithContext(ctx).Find(&dbModels).Error; err != nil {
		return nil, err
	}
	entities := make([]*model.SAMLConnection, 0)
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}
