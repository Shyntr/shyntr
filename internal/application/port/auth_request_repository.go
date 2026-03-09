package port

import (
	"context"

	"github.com/nevzatcirak/shyntr/internal/domain/entity"
)

type AuthRequestRepository interface {
	SaveLoginRequest(ctx context.Context, req *entity.LoginRequest) error
	GetLoginRequest(ctx context.Context, id string) (*entity.LoginRequest, error)
	GetRecentLogins(ctx context.Context, tenantID string, limit int) ([]entity.LoginRequest, error)
	GetAuthenticatedLoginRequest(ctx context.Context, id string) (*entity.LoginRequest, error)
	GetAuthenticatedLoginRequestBySubject(ctx context.Context, userID string) (*entity.LoginRequest, error)
	UpdateLoginRequest(ctx context.Context, req *entity.LoginRequest) error

	SaveConsentRequest(ctx context.Context, req *entity.ConsentRequest) error
	GetConsentRequest(ctx context.Context, id string) (*entity.ConsentRequest, error)
	GetAuthenticatedConsentRequest(ctx context.Context, id string) (*entity.ConsentRequest, error)
	GetAuthenticatedConsentRequestBySubject(ctx context.Context, id string) (*entity.ConsentRequest, error)
	UpdateConsentRequest(ctx context.Context, req *entity.ConsentRequest) error
}
