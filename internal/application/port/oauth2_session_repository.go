package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

type OAuth2SessionRepository interface {
	GetBySubjectAndClient(ctx context.Context, subject, clientID string) (*model.OAuth2Session, error)
	DeleteBySubjectAndClient(ctx context.Context, subject, clientID string) error
}
