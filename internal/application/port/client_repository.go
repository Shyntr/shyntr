package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

type OAuth2ClientRepository interface {
	Create(ctx context.Context, client *model.OAuth2Client) error
	GetByID(ctx context.Context, id string) (*model.OAuth2Client, error)
	GetClientCount(ctx context.Context, tenantID string) (int64, error)
	GetPublicClientCount(ctx context.Context, tenantID string) (int64, error)
	GetConfidentialClientCount(ctx context.Context, tenantID string) (int64, error)
	GetByTenantAndID(ctx context.Context, tenantID, id string) (*model.OAuth2Client, error)
	Update(ctx context.Context, client *model.OAuth2Client) error
	Delete(ctx context.Context, tenantID, id string) error
	ListByTenant(ctx context.Context, tenantID string) ([]*model.OAuth2Client, error)
	List(ctx context.Context) ([]*model.OAuth2Client, error)
}

type SAMLClientRepository interface {
	Create(ctx context.Context, client *model.SAMLClient) error
	GetByID(ctx context.Context, tenantID, id string) (*model.SAMLClient, error)
	GetByEntityID(ctx context.Context, entityID string) (*model.SAMLClient, error)
	GetByEntity(entityID string) (*model.SAMLClient, error)
	GetClientCount(ctx context.Context, tenantID string) (int64, error)
	GetByTenantAndEntityID(ctx context.Context, tenantID, entityID string) (*model.SAMLClient, error)
	Update(ctx context.Context, client *model.SAMLClient) error
	Delete(ctx context.Context, tenantID, id string) error
	ListByTenant(ctx context.Context, tenantID string) ([]*model.SAMLClient, error)
	List(ctx context.Context) ([]*model.SAMLClient, error)
}
