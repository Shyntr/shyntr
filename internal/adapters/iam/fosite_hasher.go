package iam

import (
	"context"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/ory/fosite"
)

type fositeSecretHasher struct {
	cfg *fosite.Config
}

func NewFositeSecretHasher(cfg *fosite.Config) port.SecretHasher {
	return &fositeSecretHasher{
		cfg: cfg,
	}
}

func (h *fositeSecretHasher) Hash(ctx context.Context, secret string) (string, error) {
	bytes, err := h.cfg.GetSecretsHasher(ctx).Hash(ctx, []byte(secret))
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func (h *fositeSecretHasher) Compare(ctx context.Context, hash, secret string) error {
	return h.cfg.GetSecretsHasher(ctx).Compare(ctx, []byte(hash), []byte(secret))
}
