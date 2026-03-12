package repository

import (
	"context"
	"errors"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/entity"
	"gorm.io/gorm"
)

type samlClientRepository struct {
	db *gorm.DB
}

func NewSAMLClientRepository(db *gorm.DB) port.SAMLClientRepository {
	return &samlClientRepository{db: db}
}

func (r *samlClientRepository) Create(ctx context.Context, client *entity.SAMLClient) error {
	dbModel := models.FromDomainSAMLClient(client)
	return r.db.WithContext(ctx).Create(dbModel).Error
}

func (r *samlClientRepository) GetByID(ctx context.Context, tenantID, id string) (*entity.SAMLClient, error) {
	var dbModel models.SAMLClientGORM
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).First(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("saml client not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *samlClientRepository) GetByEntityID(ctx context.Context, entityID string) (*entity.SAMLClient, error) {
	var dbModel models.SAMLClientGORM
	if err := r.db.WithContext(ctx).Where("entity_id = ?", entityID).First(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("saml client not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *samlClientRepository) GetByEntity(entityID string) (*entity.SAMLClient, error) {
	var dbModel models.SAMLClientGORM
	if err := r.db.Where("entity_id = ?", entityID).First(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("saml client not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *samlClientRepository) GetClientCount(ctx context.Context, tenantID string) (int64, error) {
	var count int64
	query := r.db.WithContext(ctx).Model(&models.SAMLClientGORM{})
	if tenantID != "" {
		query = query.Where("tenant_id = ?", tenantID)
	}
	if err := query.Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *samlClientRepository) GetByTenantAndEntityID(ctx context.Context, tenantID, entityID string) (*entity.SAMLClient, error) {
	var dbModel models.SAMLClientGORM
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND entity_id = ?", tenantID, entityID).First(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("saml client not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *samlClientRepository) Update(ctx context.Context, client *entity.SAMLClient) error {
	dbModel := models.FromDomainSAMLClient(client)
	return r.db.WithContext(ctx).Model(&models.SAMLClientGORM{}).
		Where("tenant_id = ? AND id = ?", client.TenantID, client.ID).
		Updates(dbModel).Error
}

func (r *samlClientRepository) Delete(ctx context.Context, tenantID, id string) error {
	result := r.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).Delete(&models.SAMLClientGORM{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("saml client not found or already deleted")
	}
	return nil
}

func (r *samlClientRepository) ListByTenant(ctx context.Context, tenantID string) ([]*entity.SAMLClient, error) {
	var dbModels []models.SAMLClientGORM
	query := r.db.WithContext(ctx).Model(&models.SAMLClientGORM{})
	if tenantID != "" {
		query = query.Where("tenant_id = ?", tenantID)
	}
	if err := query.Find(&dbModels).Error; err != nil {
		return nil, err
	}
	entities := make([]*entity.SAMLClient, 0)
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}

func (r *samlClientRepository) List(ctx context.Context) ([]*entity.SAMLClient, error) {
	var dbModels []models.SAMLClientGORM
	if err := r.db.WithContext(ctx).Find(&dbModels).Error; err != nil {
		return nil, err
	}

	entities := make([]*entity.SAMLClient, 0)
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}
