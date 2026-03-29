package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

type AuthRequestRepository interface {
	SaveLoginRequest(ctx context.Context, req *model.LoginRequest) error
	GetLoginRequest(ctx context.Context, id string) (*model.LoginRequest, error)
	GetRecentLogins(ctx context.Context, tenantID string, limit int) ([]model.LoginRequest, error)
	GetAuthenticatedLoginRequest(ctx context.Context, id string) (*model.LoginRequest, error)
	GetAuthenticatedLoginRequestBySubject(ctx context.Context, userID string) (*model.LoginRequest, error)
	GetLoginRequestBySessionToken(ctx context.Context, sessionToken string) (*model.LoginRequest, error)
	UpdateLoginRequest(ctx context.Context, req *model.LoginRequest) error

	SaveConsentRequest(ctx context.Context, req *model.ConsentRequest) error
	GetConsentRequest(ctx context.Context, id string) (*model.ConsentRequest, error)
	GetAuthenticatedConsentRequest(ctx context.Context, id string) (*model.ConsentRequest, error)
	GetAuthenticatedConsentRequestBySubject(ctx context.Context, id string) (*model.ConsentRequest, error)
	UpdateConsentRequest(ctx context.Context, req *model.ConsentRequest) error
}
