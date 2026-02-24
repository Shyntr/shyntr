package crypto_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nevzatcirak/shyntr/pkg/crypto"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
)

func TestHashSecret_EmptySecret(t *testing.T) {
	t.Parallel()

	cfg := &fosite.Config{
		GlobalSecret: []byte("unit-test-global-secret-unit-test-global-secret"),
	}

	got, err := crypto.HashSecret(context.Background(), cfg, "")
	require.NoError(t, err)
	require.Equal(t, "", got)
}

func TestHashSecret_CompareRoundtrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := &fosite.Config{
		GlobalSecret: []byte("unit-test-global-secret-unit-test-global-secret"),
	}

	plain := "s3cr3t-plain"
	hashed, err := crypto.HashSecret(ctx, cfg, plain)
	require.NoError(t, err)
	require.NotEmpty(t, hashed)
	require.NotEqual(t, plain, hashed)

	hasher := cfg.GetSecretsHasher(ctx)

	require.NoError(t, hasher.Compare(ctx, []byte(hashed), []byte(plain)))

	require.Error(t, hasher.Compare(ctx, []byte(hashed), []byte("wrong-secret")))
}

func TestEncryptDecryptAES_Roundtrip(t *testing.T) {
	t.Parallel()

	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	plaintext := []byte("hello-world")

	enc, err := crypto.EncryptAES(plaintext, key)
	require.NoError(t, err)
	require.NotEmpty(t, enc)

	dec, err := crypto.DecryptAES(enc, key)
	require.NoError(t, err)
	require.Equal(t, plaintext, dec)
}

func TestDecryptAES_InvalidBase64(t *testing.T) {
	t.Parallel()

	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	_, err := crypto.DecryptAES("not-base64!!!", key)
	require.Error(t, err)
}

func TestDecryptAES_CiphertextTooShort(t *testing.T) {
	t.Parallel()

	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	short := "YWJjZA=="
	_, err := crypto.DecryptAES(short, key)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "ciphertext too short") || strings.Contains(err.Error(), "message authentication failed"))
}
