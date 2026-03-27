package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type JWKSCacheOption func(*JWKSCache)

func WithClock(clock func() time.Time) JWKSCacheOption {
	return func(c *JWKSCache) {
		c.now = clock
	}
}

func WithTTL(ttl time.Duration) JWKSCacheOption {
	return func(c *JWKSCache) {
		c.ttl = ttl
	}
}

func WithGracePeriod(grace time.Duration) JWKSCacheOption {
	return func(c *JWKSCache) {
		c.gracePeriod = grace
	}
}

type cacheEntry struct {
	keys      *jose.JSONWebKeySet
	fetchedAt time.Time
}

type JWKSCache struct {
	mu          sync.RWMutex
	store       map[string]cacheEntry
	ttl         time.Duration
	gracePeriod time.Duration
	now         func() time.Time
}

func NewJWKSCache(opts ...JWKSCacheOption) *JWKSCache {
	cache := &JWKSCache{
		store:       make(map[string]cacheEntry),
		ttl:         10 * time.Minute,
		gracePeriod: 15 * time.Second,
		now:         time.Now,
	}

	for _, opt := range opts {
		opt(cache)
	}

	return cache
}

func validateJWKSURI(jwksURI string) error {
	parsedURL, err := url.ParseRequestURI(jwksURI)
	if err != nil {
		return fmt.Errorf("invalid JWKS URI format: %w", err)
	}

	if parsedURL.Scheme != "https" {
		return errors.New("security violation: JWKS URI must use the 'https' scheme")
	}

	ips, err := net.LookupIP(parsedURL.Hostname())
	if err != nil {
		return fmt.Errorf("failed to resolve JWKS URI hostname: %w", err)
	}

	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("security violation: JWKS URI hostname resolves to a restricted or private IP address (%s)", ip.String())
		}
	}

	return nil
}

// GetEncryptionKey fetches or retrieves a cached key matching the algorithm.
func (c *JWKSCache) GetEncryptionKey(ctx context.Context, jwksURI string, alg string) (interface{}, error) {
	if err := validateJWKSURI(jwksURI); err != nil {
		return nil, fmt.Errorf("SSRF validation failed for JWKS URI: %w", err)
	}

	c.mu.RLock()
	entry, exists := c.store[jwksURI]
	c.mu.RUnlock()

	currentTime := c.now()
	isStale := exists && currentTime.Sub(entry.fetchedAt) > c.ttl
	isWithinGrace := exists && currentTime.Sub(entry.fetchedAt) <= (c.ttl+c.gracePeriod)

	if exists && !isStale {
		return c.findKeyByAlg(entry.keys, alg)
	}

	newKeys, err := c.fetchJWKS(ctx, jwksURI)
	if err != nil {
		if isWithinGrace {
			return c.findKeyByAlg(entry.keys, alg)
		}
		return nil, fmt.Errorf("failed to fetch JWKS and grace period expired or unavailable: %w", err)
	}

	c.mu.Lock()
	c.store[jwksURI] = cacheEntry{
		keys:      newKeys,
		fetchedAt: currentTime,
	}
	c.mu.Unlock()

	return c.findKeyByAlg(newKeys, alg)
}

func (c *JWKSCache) fetchJWKS(ctx context.Context, uri string) (*jose.JSONWebKeySet, error) {
	if err := validateJWKSURI(uri); err != nil {
		return nil, fmt.Errorf("SSRF validation blocked fetch: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	return &jwks, nil
}

func (c *JWKSCache) findKeyByAlg(jwks *jose.JSONWebKeySet, alg string) (interface{}, error) {
	var fallbackKey interface{}

	for _, key := range jwks.Keys {
		if key.Use != "" && key.Use != "enc" {
			continue
		}

		if key.Algorithm == alg {
			return key.Key, nil
		}

		if key.Algorithm == "" && fallbackKey == nil {
			fallbackKey = key.Key
		}
	}

	if fallbackKey != nil {
		return fallbackKey, nil
	}

	return nil, errors.New("no matching encryption key found for the specified algorithm")
}
