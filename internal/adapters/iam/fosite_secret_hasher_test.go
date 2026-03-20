package iam_test

import (
	"context"
	"testing"

	"github.com/Shyntr/shyntr/internal/adapters/iam"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashSecret_Empty(t *testing.T) {
	t.Parallel()
	cfg := &fosite.Config{GlobalSecret: []byte("12345678901234567890123456789012")}
	hasher := iam.NewFositeSecretHasher(cfg)
	ctx := context.Background()

	hash, err := hasher.Hash(ctx, "")
	require.NoError(t, err, "Hashing an empty string should not panic or fail at the crypto level")

	err = hasher.Compare(ctx, hash, "")
	assert.NoError(t, err, "Compare returns nil because the underlying bcrypt successfully matches empty strings")
}

func TestHashSecret_Validates(t *testing.T) {
	t.Parallel()
	cfg := &fosite.Config{GlobalSecret: []byte("12345678901234567890123456789012")}
	hasher := iam.NewFositeSecretHasher(cfg)
	ctx := context.Background()

	secret := "super-secure-high-entropy-secret"

	hash, err := hasher.Hash(ctx, secret)
	require.NoError(t, err)
	assert.NotEmpty(t, hash, "Hash must not be empty")
	assert.NotEqual(t, secret, hash, "Hash must not be plaintext")

	err = hasher.Compare(ctx, hash, secret)
	assert.NoError(t, err, "Correct secret must validate successfully")
}

func TestHashSecret_WrongSecretFails(t *testing.T) {
	t.Parallel()
	cfg := &fosite.Config{GlobalSecret: []byte("12345678901234567890123456789012")}
	hasher := iam.NewFositeSecretHasher(cfg)
	ctx := context.Background()

	secret := "super-secure-high-entropy-secret"
	wrongSecret := "wrong-secret-value"

	hash, err := hasher.Hash(ctx, secret)
	require.NoError(t, err)

	err = hasher.Compare(ctx, hash, wrongSecret)
	assert.Error(t, err, "Wrong secret must fail validation")
}
