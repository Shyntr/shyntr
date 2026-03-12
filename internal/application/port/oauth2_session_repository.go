package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/entity"
)

type OAuth2SessionRepository interface {
	GetBySubjectAndClient(ctx context.Context, subject, clientID string) (*entity.OAuth2Session, error)
	DeleteBySubjectAndClient(ctx context.Context, subject, clientID string) error
}
