package utils

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
)

func allowAllJWKSURIs(_ context.Context, _ string) error {
	return nil
}

func newTestJWKSCache(client *http.Client, opts ...JWKSCacheOption) *JWKSCache {
	baseOpts := []JWKSCacheOption{
		WithHTTPClient(client),
		WithJWKSURIValidator(allowAllJWKSURIs),
	}
	baseOpts = append(baseOpts, opts...)
	return NewJWKSCache(baseOpts...)
}

func generateEncJWKS(alg string) (jose.JSONWebKeySet, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	pub := &privateKey.PublicKey

	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       pub,
				KeyID:     "enc-key-1",
				Algorithm: alg,
				Use:       "enc",
			},
		},
	}, pub
}

func generateFallbackJWKS() (jose.JSONWebKeySet, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	pub := &privateKey.PublicKey

	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       pub,
				KeyID:     "enc-fallback-1",
				Algorithm: "",
				Use:       "enc",
			},
		},
	}, pub
}

func generateSigOnlyJWKS() jose.JSONWebKeySet {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &privateKey.PublicKey,
				KeyID:     "sig-key-1",
				Algorithm: "RS256",
				Use:       "sig",
			},
		},
	}
}

func generateMixedJWKS(encAlg string) (jose.JSONWebKeySet, *rsa.PublicKey) {
	encPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	sigPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	encPub := &encPrivateKey.PublicKey

	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &sigPrivateKey.PublicKey,
				KeyID:     "sig-key-1",
				Algorithm: "RS256",
				Use:       "sig",
			},
			{
				Key:       encPub,
				KeyID:     "enc-key-1",
				Algorithm: encAlg,
				Use:       "enc",
			},
		},
	}, encPub
}

func testJWKSContext() context.Context {
	return context.WithValue(context.Background(), ContextKeyAllowPrivateJWKSIPs, true)
}

func TestJWKSCache_Fetch_PositivePath(t *testing.T) {
	t.Parallel()

	jwks, expectedKey := generateEncJWKS("RSA-OAEP")
	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	cache := newTestJWKSCache(server.Client())
	ctx := testJWKSContext()

	key, err := cache.GetEncryptionKey(ctx, server.URL, "RSA-OAEP")

	require.NoError(t, err)
	require.NotNil(t, key)

	got, ok := key.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, expectedKey.N, got.N)
	assert.Equal(t, expectedKey.E, got.E)
}

func TestJWKSCache_UsesCachedValueWithinTTL(t *testing.T) {
	t.Parallel()

	jwks, expectedKey := generateEncJWKS("RSA-OAEP")
	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)
	var requestCount atomic.Int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	baseTime := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)
	var currentTime atomic.Value
	currentTime.Store(baseTime)

	cache := newTestJWKSCache(server.Client(), WithClock(func() time.Time {
		return currentTime.Load().(time.Time)
	}), WithTTL(10*time.Minute))
	ctx := testJWKSContext()

	key1, err := cache.GetEncryptionKey(ctx, server.URL, "RSA-OAEP")
	require.NoError(t, err)

	currentTime.Store(baseTime.Add(3 * time.Minute))

	key2, err := cache.GetEncryptionKey(ctx, server.URL, "RSA-OAEP")
	require.NoError(t, err)

	assert.Equal(t, int32(1), requestCount.Load())

	got1 := key1.(*rsa.PublicKey)
	got2 := key2.(*rsa.PublicKey)
	assert.Equal(t, expectedKey.N, got1.N)
	assert.Equal(t, expectedKey.N, got2.N)
}

func TestJWKSCache_NetworkFailure_GracePeriod(t *testing.T) {
	t.Parallel()

	jwks, expectedKey := generateEncJWKS("RSA-OAEP")
	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)
	var shouldFail atomic.Bool

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if shouldFail.Load() {
			http.Error(w, "temporary failure", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	baseTime := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)
	var currentTime atomic.Value
	currentTime.Store(baseTime)

	cache := newTestJWKSCache(server.Client(), WithClock(func() time.Time {
		return currentTime.Load().(time.Time)
	}), WithTTL(10*time.Minute), WithGracePeriod(30*time.Second))
	ctx := testJWKSContext()

	key1, err := cache.GetEncryptionKey(ctx, server.URL, "RSA-OAEP")
	require.NoError(t, err)

	shouldFail.Store(true)
	currentTime.Store(baseTime.Add(10*time.Minute + 15*time.Second))

	key2, err := cache.GetEncryptionKey(ctx, server.URL, "RSA-OAEP")
	require.NoError(t, err)

	got1 := key1.(*rsa.PublicKey)
	got2 := key2.(*rsa.PublicKey)
	assert.Equal(t, expectedKey.N, got1.N)
	assert.Equal(t, expectedKey.N, got2.N)
}

func TestJWKSCache_GracePeriodExpired_ReturnsError(t *testing.T) {
	t.Parallel()

	jwks, _ := generateEncJWKS("RSA-OAEP")
	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)
	var shouldFail atomic.Bool

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if shouldFail.Load() {
			http.Error(w, "temporary failure", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	baseTime := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)
	var currentTime atomic.Value
	currentTime.Store(baseTime)

	cache := newTestJWKSCache(server.Client(), WithClock(func() time.Time {
		return currentTime.Load().(time.Time)
	}), WithTTL(10*time.Minute), WithGracePeriod(30*time.Second))
	ctx := testJWKSContext()

	_, err = cache.GetEncryptionKey(ctx, server.URL, "RSA-OAEP")
	require.NoError(t, err)

	shouldFail.Store(true)
	currentTime.Store(baseTime.Add(16 * time.Minute))

	key, err := cache.GetEncryptionKey(ctx, server.URL, "RSA-OAEP")
	require.Error(t, err)
	require.Nil(t, key)
	assert.Contains(t, err.Error(), "failed to fetch JWKS and grace period expired or unavailable")
}

func TestJWKSCache_NegativePath_InvalidPayload(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":"not-an-array"}`))
	}))
	defer server.Close()

	cache := newTestJWKSCache(server.Client())
	ctx := testJWKSContext()

	key, err := cache.GetEncryptionKey(ctx, server.URL, "RSA-OAEP")
	require.Error(t, err)
	require.Nil(t, key)
}

func TestJWKSCache_NegativePath_Non200(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cache := newTestJWKSCache(server.Client())
	ctx := testJWKSContext()

	key, err := cache.GetEncryptionKey(ctx, server.URL, "RSA-OAEP")
	require.Error(t, err)
	require.Nil(t, key)
	assert.Contains(t, err.Error(), "unexpected status code")
}

func TestJWKSCache_FallbackKey_WhenAlgorithmEmpty(t *testing.T) {
	t.Parallel()

	jwks, expectedKey := generateFallbackJWKS()
	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	cache := newTestJWKSCache(server.Client())
	ctx := testJWKSContext()

	key, err := cache.GetEncryptionKey(ctx, server.URL, "RSA-OAEP")
	require.NoError(t, err)

	got, ok := key.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, expectedKey.N, got.N)
	assert.Equal(t, expectedKey.E, got.E)
}

func TestJWKSCache_IgnoreSignatureKeys_UsesEncryptionKey(t *testing.T) {
	t.Parallel()

	jwks, expectedKey := generateMixedJWKS("RSA-OAEP")
	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	cache := newTestJWKSCache(server.Client())
	ctx := testJWKSContext()

	key, err := cache.GetEncryptionKey(ctx, server.URL, "RSA-OAEP")
	require.NoError(t, err)

	got, ok := key.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, expectedKey.N, got.N)
}

func TestJWKSCache_SignatureOnlyJWKS_ReturnsNoMatchingKey(t *testing.T) {
	t.Parallel()

	jwks := generateSigOnlyJWKS()
	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	cache := newTestJWKSCache(server.Client())
	ctx := testJWKSContext()

	key, err := cache.GetEncryptionKey(ctx, server.URL, "RSA-OAEP")
	require.Error(t, err)
	require.Nil(t, key)
	assert.Contains(t, err.Error(), "no matching encryption key found")
}

func TestJWKSCache_Concurrency_MutexLockContention(t *testing.T) {
	t.Parallel()

	jwks, _ := generateEncJWKS("RSA-OAEP")
	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)
	var requestCount atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer server.Close()

	cache := newTestJWKSCache(server.Client())
	ctx := testJWKSContext()

	var wg sync.WaitGroup
	results := make(chan error, 20)

	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cache.GetEncryptionKey(ctx, server.URL, "RSA-OAEP")
			results <- err
		}()
	}

	wg.Wait()
	close(results)

	for err := range results {
		assert.NoError(t, err)
	}

	assert.Equal(t, int32(1), requestCount.Load())
}

func TestJWKSCache_ValidationFailure_HttpScheme(t *testing.T) {
	t.Parallel()

	cache := NewJWKSCache()
	ctx := testJWKSContext()

	key, err := cache.GetEncryptionKey(ctx, "http://example.com/jwks", "RSA-OAEP")
	require.Error(t, err)
	require.Nil(t, key)
	assert.Contains(t, err.Error(), "must use the 'https' scheme")
}

func TestJWKSCache_ValidationFailure_PrivateIPWithoutOverride(t *testing.T) {
	t.Parallel()

	cache := NewJWKSCache()

	key, err := cache.GetEncryptionKey(context.Background(), "https://127.0.0.1/jwks", "RSA-OAEP")
	require.Error(t, err)
	require.Nil(t, key)
	assert.Contains(t, err.Error(), "restricted IP address")
}
