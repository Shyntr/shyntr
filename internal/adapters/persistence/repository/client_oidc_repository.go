package repository

import (
	"context"
	"errors"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/entity"
	"gorm.io/gorm"
)

type oauth2ClientRepository struct {
	db *gorm.DB
}

func NewOAuth2ClientRepository(db *gorm.DB) port.OAuth2ClientRepository {
	return &oauth2ClientRepository{db: db}
}

func (r *oauth2ClientRepository) Create(ctx context.Context, client *entity.OAuth2Client) error {
	dbModel := models.FromDomainOAuth2Client(client)
	return r.db.WithContext(ctx).Create(dbModel).Error
}

func (r *oauth2ClientRepository) GetByID(ctx context.Context, id string) (*entity.OAuth2Client, error) {
	var dbModel models.OAuth2ClientGORM
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("oauth2 client not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *oauth2ClientRepository) GetClientCount(ctx context.Context, tenantID string) (int64, error) {
	var count int64
	query := r.db.WithContext(ctx).Model(&models.OAuth2ClientGORM{})
	if tenantID != "" {
		query = query.Where("tenant_id = ?", tenantID)
	}
	if err := query.Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *oauth2ClientRepository) GetPublicClientCount(ctx context.Context, tenantID string) (int64, error) {
	var count int64
	query := r.db.WithContext(ctx).Model(&models.OAuth2ClientGORM{}).Where("public = ?", true)
	if tenantID != "" {
		query = query.Where("tenant_id = ?", tenantID)
	}
	if err := query.Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *oauth2ClientRepository) GetConfidentialClientCount(ctx context.Context, tenantID string) (int64, error) {
	var count int64
	query := r.db.WithContext(ctx).Model(&models.OAuth2ClientGORM{}).Where("public = ?", false)
	if tenantID != "" {
		query = query.Where("tenant_id = ?", tenantID)
	}
	if err := query.Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (r *oauth2ClientRepository) GetByTenantAndID(ctx context.Context, tenantID, id string) (*entity.OAuth2Client, error) {
	var dbModel models.OAuth2ClientGORM
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).First(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("oauth2 client not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *oauth2ClientRepository) Update(ctx context.Context, client *entity.OAuth2Client) error {
	dbModel := models.FromDomainOAuth2Client(client)
	return r.db.WithContext(ctx).Model(&models.OAuth2ClientGORM{}).
		Where("tenant_id = ? AND id = ?", client.TenantID, client.ID).
		Updates(dbModel).Error
}

func (r *oauth2ClientRepository) Delete(ctx context.Context, tenantID, id string) error {
	result := r.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, id).Delete(&models.OAuth2ClientGORM{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("client not found or already deleted")
	}
	return nil
}

func (r *oauth2ClientRepository) ListByTenant(ctx context.Context, tenantID string) ([]*entity.OAuth2Client, error) {
	var dbModels []models.OAuth2ClientGORM
	query := r.db.WithContext(ctx).Model(&models.OAuth2ClientGORM{})
	if tenantID != "" {
		query = query.Where("tenant_id = ?", tenantID)
	}
	if err := query.Find(&dbModels).Error; err != nil {
		return nil, err
	}
	entities := make([]*entity.OAuth2Client, 0)
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}

func (r *oauth2ClientRepository) List(ctx context.Context) ([]*entity.OAuth2Client, error) {
	var dbModels []models.OAuth2ClientGORM
	if err := r.db.WithContext(ctx).Find(&dbModels).Error; err != nil {
		return nil, err
	}

	// FIX: Initialize slice strictly to avoid `null` JSON response.
	entities := make([]*entity.OAuth2Client, 0)
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}
