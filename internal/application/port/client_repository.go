package port

import (
	"context"

	"github.com/nevzatcirak/shyntr/internal/domain/entity"
)

type OAuth2ClientRepository interface {
	Create(ctx context.Context, client *entity.OAuth2Client) error
	GetByID(ctx context.Context, id string) (*entity.OAuth2Client, error)
	GetClientCount(ctx context.Context, tenantID string) (int64, error)
	GetPublicClientCount(ctx context.Context, tenantID string) (int64, error)
	GetConfidentialClientCount(ctx context.Context, tenantID string) (int64, error)
	GetByTenantAndID(ctx context.Context, tenantID, id string) (*entity.OAuth2Client, error)
	Update(ctx context.Context, client *entity.OAuth2Client) error
	Delete(ctx context.Context, tenantID, id string) error
	ListByTenant(ctx context.Context, tenantID string) ([]*entity.OAuth2Client, error)
	List(ctx context.Context) ([]*entity.OAuth2Client, error)
}

type SAMLClientRepository interface {
	Create(ctx context.Context, client *entity.SAMLClient) error
	GetByID(ctx context.Context, tenantID, id string) (*entity.SAMLClient, error)
	GetByEntityID(ctx context.Context, entityID string) (*entity.SAMLClient, error)
	GetByEntity(entityID string) (*entity.SAMLClient, error)
	GetClientCount(ctx context.Context, tenantID string) (int64, error)
	GetByTenantAndEntityID(ctx context.Context, tenantID, entityID string) (*entity.SAMLClient, error)
	Update(ctx context.Context, client *entity.SAMLClient) error
	Delete(ctx context.Context, tenantID, id string) error
	ListByTenant(ctx context.Context, tenantID string) ([]*entity.SAMLClient, error)
	List(ctx context.Context) ([]*entity.SAMLClient, error)
}
