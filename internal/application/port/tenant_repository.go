package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

type TenantRepository interface {
	Create(ctx context.Context, tenant *model.Tenant) error
	GetByID(ctx context.Context, id string) (*model.Tenant, error)
	GetByName(ctx context.Context, name string) (*model.Tenant, error)
	GetCount(ctx context.Context) (int64, error)
	Update(ctx context.Context, tenant *model.Tenant) error
	Delete(ctx context.Context, id string) error
	CascadeDelete(ctx context.Context, id string) error
	List(ctx context.Context) ([]*model.Tenant, error)
}
