package repository

import (
	"context"
	"errors"

	"github.com/nevzatcirak/shyntr/internal/adapters/persistence/models"
	"github.com/nevzatcirak/shyntr/internal/application/port"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
	"gorm.io/gorm"
)

type authRequestRepository struct {
	db *gorm.DB
}

func NewAuthRequestRepository(db *gorm.DB) port.AuthRequestRepository {
	return &authRequestRepository{db: db}
}

func (r *authRequestRepository) SaveLoginRequest(ctx context.Context, req *entity.LoginRequest) error {
	dbModel := models.FromDomainLoginRequest(req)
	return r.db.WithContext(ctx).Create(dbModel).Error
}

func (r *authRequestRepository) GetLoginRequest(ctx context.Context, id string) (*entity.LoginRequest, error) {
	var dbModel models.LoginRequestGORM
	if err := r.db.WithContext(ctx).First(&dbModel, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("login request not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *authRequestRepository) GetRecentLogins(ctx context.Context, tenantID string, limit int) ([]entity.LoginRequest, error) {
	var dbModel []models.LoginRequestGORM
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Order("created_at desc").Limit(limit).Find(&dbModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("login request not found")
		}
		return nil, err
	}
	return models.ToDomainLoginRequestList(dbModel), nil
}

func (r *authRequestRepository) GetAuthenticatedLoginRequest(ctx context.Context, id string) (*entity.LoginRequest, error) {
	var dbModel models.LoginRequestGORM
	if err := r.db.WithContext(ctx).First(&dbModel, "id = ? AND authenticated = ?", id, true).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("login request not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *authRequestRepository) GetAuthenticatedLoginRequestBySubject(ctx context.Context, userID string) (*entity.LoginRequest, error) {
	var dbModel models.LoginRequestGORM
	if err := r.db.WithContext(ctx).First(&dbModel, "subject = ? AND authenticated = ?", userID, true).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("login request not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *authRequestRepository) UpdateLoginRequest(ctx context.Context, req *entity.LoginRequest) error {
	dbModel := models.FromDomainLoginRequest(req)
	return r.db.WithContext(ctx).Save(dbModel).Error
}

func (r *authRequestRepository) SaveConsentRequest(ctx context.Context, req *entity.ConsentRequest) error {
	dbModel := models.FromDomainConsentRequest(req)
	return r.db.WithContext(ctx).Create(dbModel).Error
}

func (r *authRequestRepository) GetConsentRequest(ctx context.Context, id string) (*entity.ConsentRequest, error) {
	var dbModel models.ConsentRequestGORM
	if err := r.db.WithContext(ctx).First(&dbModel, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("consent request not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *authRequestRepository) GetAuthenticatedConsentRequest(ctx context.Context, id string) (*entity.ConsentRequest, error) {
	var dbModel models.ConsentRequestGORM
	if err := r.db.WithContext(ctx).First(&dbModel, "id = ? AND authenticated = ?", id, true).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("consent request not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *authRequestRepository) GetAuthenticatedConsentRequestBySubject(ctx context.Context, userID string) (*entity.ConsentRequest, error) {
	var dbModel models.ConsentRequestGORM
	if err := r.db.WithContext(ctx).First(&dbModel, "subject = ? AND authenticated = ?", userID, true).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("consent request not found")
		}
		return nil, err
	}
	return dbModel.ToDomain(), nil
}

func (r *authRequestRepository) UpdateConsentRequest(ctx context.Context, req *entity.ConsentRequest) error {
	dbModel := models.ConsentRequestToUpdateMap(req)
	return r.db.WithContext(ctx).Model(&models.ConsentRequestGORM{}).
		Where("id = ?", req.ID).
		Updates(dbModel).Error
}
