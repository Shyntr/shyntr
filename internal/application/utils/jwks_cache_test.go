package utils_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Shyntr/shyntr/internal/application/utils"
)

func generateJWKS() (jose.JSONWebKeySet, string) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyID := "test-key-id-1"

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &privateKey.PublicKey,
				KeyID:     keyID,
				Algorithm: "RS256",
				Use:       "sig",
			},
		},
	}
	return jwks, keyID
}

func TestJWKSCache_Fetch_PositivePath(t *testing.T) {
	t.Parallel()

	jwks, _ := generateJWKS()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	cache := utils.NewJWKSCache()
	ctx := context.Background()

	key, err := cache.GetEncryptionKey(ctx, server.URL, "RS256")

	require.NoError(t, err)
	require.NotNil(t, key)

	_, isRSA := key.(*rsa.PublicKey)
	assert.True(t, isRSA, "Expected key to be parsed and returned as *rsa.PublicKey")
}

func TestJWKSCache_NetworkFailure_GracePeriod(t *testing.T) {
	t.Parallel()

	jwks, _ := generateJWKS()
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count == 1 {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jwks)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	mockTime := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return mockTime }

	cache := utils.NewJWKSCache(
		utils.WithClock(clock),
		utils.WithTTL(10*time.Minute),
		utils.WithGracePeriod(5*time.Minute),
	)
	ctx := context.Background()

	key1, err := cache.GetEncryptionKey(ctx, server.URL, "RS256")
	require.NoError(t, err)
	require.NotNil(t, key1)

	mockTime = mockTime.Add(12 * time.Minute)

	key2, err := cache.GetEncryptionKey(ctx, server.URL, "RS256")

	require.NoError(t, err, "Cache should tolerate network failure using grace period")
	require.Equal(t, key1, key2, "Served key must match the stale cache exactly")

	mockTime = mockTime.Add(4 * time.Minute)

	key3, err := cache.GetEncryptionKey(ctx, server.URL, "RS256")
	require.Error(t, err, "Must fail hard if IdP is down and Grace Period is fully expired")
	require.Nil(t, key3)
	assert.Contains(t, err.Error(), "grace period expired")
}

func TestJWKSCache_Concurrency_MutexLockContention(t *testing.T) {
	t.Parallel()

	jwks, _ := generateJWKS()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	cache := utils.NewJWKSCache()
	ctx := context.Background()

	const concurrencyLevel = 50
	var wg sync.WaitGroup
	errs := make([]error, concurrencyLevel)
	keys := make([]interface{}, concurrencyLevel)

	wg.Add(concurrencyLevel)

	for i := 0; i < concurrencyLevel; i++ {
		go func(idx int) {
			defer wg.Done()
			key, err := cache.GetEncryptionKey(ctx, server.URL, "RS256")
			keys[idx] = key
			errs[idx] = err
		}(i)
	}

	wg.Wait()

	for i := 0; i < concurrencyLevel; i++ {
		require.NoError(t, errs[i])
		require.NotNil(t, keys[i])
	}
}

func TestJWKSCache_NegativePath_InvalidPayload(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{ "keys": [ { "kty": "RSA", "malformed_key...`))
	}))
	defer server.Close()

	cache := utils.NewJWKSCache()
	ctx := context.Background()

	key, err := cache.GetEncryptionKey(ctx, server.URL, "RS256")

	require.Error(t, err)
	require.Nil(t, key)
	assert.Contains(t, err.Error(), "failed", "Should return some form of parsing or fetching error")
}
