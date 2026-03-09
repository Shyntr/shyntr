package repository

import (
	"context"

	"github.com/nevzatcirak/shyntr/internal/adapters/persistence/models"
	"github.com/nevzatcirak/shyntr/internal/application/port"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
	"gorm.io/gorm"
)

// --- SIGNING KEY REPO ---

type signingKeyRepository struct{ db *gorm.DB }

func NewSigningKeyRepository(db *gorm.DB) port.SigningKeyRepository {
	return &signingKeyRepository{db: db}
}

func (r *signingKeyRepository) Save(ctx context.Context, key *entity.SigningKey) error {
	dbModel := models.FromDomainSigningKey(key)
	return r.db.WithContext(ctx).Create(dbModel).Error
}

func (r *signingKeyRepository) GetActiveKeysByTenant(ctx context.Context, tenantID, use string) ([]*entity.SigningKey, error) {
	var dbModels []models.SigningKeyGORM
	query := r.db.WithContext(ctx).Where("tenant_id = ? AND is_active = ?", tenantID, true)
	if use != "" {
		query = query.Where("use = ?", use)
	}
	if err := query.Find(&dbModels).Error; err != nil {
		return nil, err
	}
	var entities []*entity.SigningKey
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}

func (r *signingKeyRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Where("id = ?", id).Delete(&models.SigningKeyGORM{}).Error
}

// --- BLACKLISTED JTI REPO ---

type blacklistedJTIRepository struct{ db *gorm.DB }

func NewBlacklistedJTIRepository(db *gorm.DB) port.BlacklistedJTIRepository {
	return &blacklistedJTIRepository{db: db}
}

func (r *blacklistedJTIRepository) Save(ctx context.Context, jti *entity.BlacklistedJTI) error {
	dbModel := models.FromDomainBlacklistedJTI(jti)
	return r.db.WithContext(ctx).Create(dbModel).Error
}

func (r *blacklistedJTIRepository) Exists(ctx context.Context, jti string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.BlacklistedJTIGORM{}).Where("jti = ?", jti).Count(&count).Error
	return count > 0, err
}
