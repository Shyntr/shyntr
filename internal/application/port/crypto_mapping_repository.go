package port

import (
	"context"

	"github.com/nevzatcirak/shyntr/internal/domain/entity"
)

type SigningKeyRepository interface {
	Save(ctx context.Context, key *entity.SigningKey) error
	GetActiveKeysByTenant(ctx context.Context, tenantID, use string) ([]*entity.SigningKey, error)
	Delete(ctx context.Context, id string) error
}

type BlacklistedJTIRepository interface {
	Save(ctx context.Context, jti *entity.BlacklistedJTI) error
	Exists(ctx context.Context, jti string) (bool, error)
}
