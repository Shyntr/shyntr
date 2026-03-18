package repository

import (
	"context"
	"errors"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"gorm.io/gorm"
)

type cryptoKeyRepository struct {
	db *gorm.DB
}

func NewCryptoKeyRepository(db *gorm.DB) port.CryptoKeyRepository {
	return &cryptoKeyRepository{db: db}
}

func (r *cryptoKeyRepository) Save(ctx context.Context, key *model.CryptoKey) error {
	gormModel := models.FromDomainCryptoKey(key)
	return r.db.WithContext(ctx).Save(gormModel).Error
}

func (r *cryptoKeyRepository) GetActiveKey(ctx context.Context, use string) (*model.CryptoKey, error) {
	var gormModel models.CryptoKeyGORM

	err := r.db.WithContext(ctx).
		Where("use = ? AND state = ?", use, model.KeyStateActive).
		First(&gormModel).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("critical: no active key found for use type " + use)
		}
		return nil, err
	}

	return gormModel.ToDomain(), nil
}

func (r *cryptoKeyRepository) GetKeysByStates(ctx context.Context, use string, states []model.KeyState) ([]*model.CryptoKey, error) {
	var gormModels []models.CryptoKeyGORM
	err := r.db.WithContext(ctx).
		Where("use = ? AND state IN ?", use, states).
		Find(&gormModels).Error

	if err != nil {
		return nil, err
	}

	var domainModels []*model.CryptoKey
	for _, m := range gormModels {
		domainModels = append(domainModels, m.ToDomain())
	}

	return domainModels, nil
}

func (r *cryptoKeyRepository) DeleteKey(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Unscoped().Where("id = ?", id).Delete(&models.CryptoKeyGORM{}).Error
}

// --- BLACKLISTED JTI REPO ---

type blacklistedJTIRepository struct{ db *gorm.DB }

func NewBlacklistedJTIRepository(db *gorm.DB) port.BlacklistedJTIRepository {
	return &blacklistedJTIRepository{db: db}
}

func (r *blacklistedJTIRepository) Save(ctx context.Context, jti *model.BlacklistedJTI) error {
	dbModel := models.FromDomainBlacklistedJTI(jti)
	return r.db.WithContext(ctx).Create(dbModel).Error
}

func (r *blacklistedJTIRepository) Exists(ctx context.Context, jti string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.BlacklistedJTIGORM{}).Where("jti = ?", jti).Count(&count).Error
	return count > 0, err
}
