package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

type OIDCConnectionRepository interface {
	Create(ctx context.Context, conn *model.OIDCConnection) error
	GetByID(ctx context.Context, id string) (*model.OIDCConnection, error)
	GetByTenantAndID(ctx context.Context, tenantID, id string) (*model.OIDCConnection, error)
	GetConnectionCount(ctx context.Context, tenantID string) (int64, error)
	Update(ctx context.Context, conn *model.OIDCConnection) error
	Delete(ctx context.Context, tenantID, id string) error
	ListByTenant(ctx context.Context, tenantID string) ([]*model.OIDCConnection, error)
	ListActiveByTenant(ctx context.Context, tenantID string) ([]*model.OIDCConnection, error)
	List(ctx context.Context) ([]*model.OIDCConnection, error)
}

type SAMLConnectionRepository interface {
	Create(ctx context.Context, conn *model.SAMLConnection) error
	GetByID(ctx context.Context, id string) (*model.SAMLConnection, error)
	GetByTenantAndID(ctx context.Context, tenantID, id string) (*model.SAMLConnection, error)
	GetConnectionCount(ctx context.Context, tenantID string) (int64, error)
	GetConnectionByIdpEntity(ctx context.Context, tenantID, idpEntity string) (*model.SAMLConnection, error)
	Update(ctx context.Context, conn *model.SAMLConnection) error
	Delete(ctx context.Context, tenantID, id string) error
	ListByTenant(ctx context.Context, tenantID string) ([]*model.SAMLConnection, error)
	ListActiveByTenant(ctx context.Context, tenantID string) ([]*model.SAMLConnection, error)
	List(ctx context.Context) ([]*model.SAMLConnection, error)
}

type LDAPConnectionRepository interface {
	Create(ctx context.Context, conn *model.LDAPConnection) error
	GetByTenantAndID(ctx context.Context, tenantID, id string) (*model.LDAPConnection, error)
	GetConnectionCount(ctx context.Context, tenantID string) (int64, error)
	Update(ctx context.Context, conn *model.LDAPConnection) error
	Delete(ctx context.Context, tenantID, id string) error
	ListByTenant(ctx context.Context, tenantID string) ([]*model.LDAPConnection, error)
	ListActiveByTenant(ctx context.Context, tenantID string) ([]*model.LDAPConnection, error)
	List(ctx context.Context) ([]*model.LDAPConnection, error)
}
