package usecase

import (
	"context"

	"github.com/nevzatcirak/shyntr/internal/application/port"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
)

type OAuth2SessionUseCase interface {
	GetBySubject(ctx context.Context, subject, clientID string) (*entity.OAuth2Session, error)
	DeleteBySubject(ctx context.Context, subject, clientID string) error
}

type oauth2SessionUseCase struct {
	repo  port.OAuth2SessionRepository
	audit port.AuditLogger
}

func NewOAuth2SessionUseCase(repo port.OAuth2SessionRepository, audit port.AuditLogger) OAuth2SessionUseCase {
	return &oauth2SessionUseCase{
		repo:  repo,
		audit: audit,
	}
}

func (o *oauth2SessionUseCase) GetBySubject(ctx context.Context, subject, clientID string) (*entity.OAuth2Session, error) {
	return o.repo.GetBySubjectAndClient(ctx, subject, clientID)
}

func (o *oauth2SessionUseCase) DeleteBySubject(ctx context.Context, subject, clientID string) error {
	return o.repo.DeleteBySubjectAndClient(ctx, subject, clientID)
}
