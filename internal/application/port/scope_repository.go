package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/entity"
)

type ScopeRepository interface {
	Create(ctx context.Context, scope *entity.Scope) error
	GetByID(ctx context.Context, tenantID, id string) (*entity.Scope, error)
	GetByName(ctx context.Context, tenantID, name string) (*entity.Scope, error)
	ListByTenant(ctx context.Context, tenantID string) ([]*entity.Scope, error)
	Update(ctx context.Context, scope *entity.Scope) error
	Delete(ctx context.Context, tenantID, id string) error
}
