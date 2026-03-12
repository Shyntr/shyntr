package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/entity"
)

type OIDCConnectionRepository interface {
	Create(ctx context.Context, conn *entity.OIDCConnection) error
	GetByID(ctx context.Context, id string) (*entity.OIDCConnection, error)
	GetByTenantAndID(ctx context.Context, tenantID, id string) (*entity.OIDCConnection, error)
	GetConnectionCount(ctx context.Context, tenantID string) (int64, error)
	Update(ctx context.Context, conn *entity.OIDCConnection) error
	Delete(ctx context.Context, tenantID, id string) error
	ListByTenant(ctx context.Context, tenantID string) ([]*entity.OIDCConnection, error)
	ListActiveByTenant(ctx context.Context, tenantID string) ([]*entity.OIDCConnection, error)
	List(ctx context.Context) ([]*entity.OIDCConnection, error)
}

type SAMLConnectionRepository interface {
	Create(ctx context.Context, conn *entity.SAMLConnection) error
	GetByID(ctx context.Context, id string) (*entity.SAMLConnection, error)
	GetByTenantAndID(ctx context.Context, tenantID, id string) (*entity.SAMLConnection, error)
	GetConnectionCount(ctx context.Context, tenantID string) (int64, error)
	GetConnectionByIdpEntity(ctx context.Context, tenantID, idpEntity string) (*entity.SAMLConnection, error)
	Update(ctx context.Context, conn *entity.SAMLConnection) error
	Delete(ctx context.Context, tenantID, id string) error
	ListByTenant(ctx context.Context, tenantID string) ([]*entity.SAMLConnection, error)
	ListActiveByTenant(ctx context.Context, tenantID string) ([]*entity.SAMLConnection, error)
	List(ctx context.Context) ([]*entity.SAMLConnection, error)
}
