package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

type ScopeRepository interface {
	Create(ctx context.Context, scope *model.Scope) error
	GetByID(ctx context.Context, tenantID, id string) (*model.Scope, error)
	GetByName(ctx context.Context, tenantID, name string) (*model.Scope, error)
	ListByTenant(ctx context.Context, tenantID string) ([]*model.Scope, error)
	Update(ctx context.Context, scope *model.Scope) error
	Delete(ctx context.Context, tenantID, id string) error
}
