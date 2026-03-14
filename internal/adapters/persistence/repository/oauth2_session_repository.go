package repository

import (
	"context"
	"errors"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"gorm.io/gorm"
)

type oauth2SessionRepository struct {
	db *gorm.DB
}

func NewOAuth2SessionRepository(db *gorm.DB) port.OAuth2SessionRepository {
	return &oauth2SessionRepository{db: db}
}

func (r *oauth2SessionRepository) GetBySubjectAndClient(ctx context.Context, subject, clientID string) (*model.OAuth2Session, error) {
	var dbModel models.OAuth2SessionGORM
	if err := r.db.WithContext(ctx).Where("client_id = ? AND subject = ?", clientID, subject).First(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("oauth2 session connection not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *oauth2SessionRepository) DeleteBySubjectAndClient(ctx context.Context, subject, clientID string) error {
	result := r.db.WithContext(ctx).Where("client_id = ? AND subject = ?", clientID, subject).Delete(&models.OAuth2SessionGORM{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("oauth2 session connection not found")
	}
	return nil
}
