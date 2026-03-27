package port

import (
	"context"
	"errors"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

var ErrKeyNotFound = errors.New("critical: no active key found for use type ")

type CryptoKeyRepository interface {
	Save(ctx context.Context, key *model.CryptoKey) error
	GetActiveKey(ctx context.Context, use string) (*model.CryptoKey, error)
	GetKeysByStates(ctx context.Context, use string, states []model.KeyState) ([]*model.CryptoKey, error)
	DeleteKey(ctx context.Context, id string) error
}

type BlacklistedJTIRepository interface {
	Save(ctx context.Context, jti *model.BlacklistedJTI) error
	Exists(ctx context.Context, jti string) (bool, error)
}
