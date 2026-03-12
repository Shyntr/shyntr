package port

import "context"

// SecretHasher defines the contract for securely hashing OAuth2 client secrets.
// This isolates the UseCase from knowing about Fosite directly.
type SecretHasher interface {
	Hash(ctx context.Context, secret string) (string, error)
	Compare(ctx context.Context, hash, secret string) error
}
