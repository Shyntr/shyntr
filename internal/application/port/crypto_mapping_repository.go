package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

type SigningKeyRepository interface {
	Save(ctx context.Context, key *model.SigningKey) error
	GetActiveKeysByTenant(ctx context.Context, tenantID, use string) ([]*model.SigningKey, error)
	Delete(ctx context.Context, id string) error
}

type BlacklistedJTIRepository interface {
	Save(ctx context.Context, jti *model.BlacklistedJTI) error
	Exists(ctx context.Context, jti string) (bool, error)
}
