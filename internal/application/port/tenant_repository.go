package port

import (
	"context"

	"github.com/nevzatcirak/shyntr/internal/domain/entity"
)

type TenantRepository interface {
	Create(ctx context.Context, tenant *entity.Tenant) error
	GetByID(ctx context.Context, id string) (*entity.Tenant, error)
	GetByName(ctx context.Context, name string) (*entity.Tenant, error)
	GetCount(ctx context.Context) (int64, error)
	Update(ctx context.Context, tenant *entity.Tenant) error
	Delete(ctx context.Context, id string) error
	CascadeDelete(ctx context.Context, id string) error
	List(ctx context.Context) ([]*entity.Tenant, error)
}
