package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/data/repository"
	"github.com/nevzatcirak/shyntr/pkg/crypto"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type ClientService struct {
	Repo   *repository.OIDCRepository
	Config *config.Config
}

func NewClientService(repo *repository.OIDCRepository, cfg *config.Config) *ClientService {
	return &ClientService{
		Repo:   repo,
		Config: cfg,
	}
}

func (s *ClientService) InitiateAuth(ctx context.Context, tenantID, connectionID, loginChallenge string) (string, error) {
	conn, err := s.Repo.GetConnection(ctx, connectionID)
	if err != nil {
		return "", fmt.Errorf("connection not found: %w", err)
	}

	if conn.AuthorizationEndpoint == "" || conn.TokenEndpoint == "" {
		if conn.IssuerURL == "" {
			return "", errors.New("neither endpoints nor issuer_url provided")
		}
		discovered, err := s.discoverEndpoints(ctx, conn.IssuerURL)
		if err != nil {
			return "", fmt.Errorf("oidc discovery failed: %w", err)
		}
		conn.AuthorizationEndpoint = discovered.AuthorizationEndpoint
		conn.TokenEndpoint = discovered.TokenEndpoint
		conn.UserInfoEndpoint = discovered.UserInfoEndpoint
		conn.JWKSURI = discovered.JWKSURI
	}

	redirectURL := fmt.Sprintf("%s/t/%s/oidc/callback", s.Config.BaseIssuerURL, tenantID)

	oauth2Config := &oauth2.Config{
		ClientID:     conn.ClientID,
		ClientSecret: conn.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  conn.AuthorizationEndpoint,
			TokenURL: conn.TokenEndpoint,
		},
		RedirectURL: redirectURL,
		Scopes:      conn.Scopes,
	}

	plainState := fmt.Sprintf("%s|%s", loginChallenge, connectionID)
	encryptedState, err := crypto.EncryptAES([]byte(plainState), []byte(s.Config.AppSecret))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt state: %w", err)
	}

	return oauth2Config.AuthCodeURL(encryptedState), nil
}

func (s *ClientService) VerifyState(encryptedState string) (loginChallenge, connectionID string, err error) {
	decryptedBytes, err := crypto.DecryptAES(encryptedState, []byte(s.Config.AppSecret))
	if err != nil {
		return "", "", fmt.Errorf("invalid state signature: %w", err)
	}

	parts := strings.Split(string(decryptedBytes), "|")
	if len(parts) != 2 {
		return "", "", errors.New("malformed state payload")
	}

	return parts[0], parts[1], nil
}

func (s *ClientService) ExchangeAndUserInfo(ctx context.Context, tenantID, code, connectionID string) (map[string]interface{}, error) {
	conn, err := s.Repo.GetConnection(ctx, connectionID)
	if err != nil {
		return nil, fmt.Errorf("connection not found: %w", err)
	}

	if conn.TokenEndpoint == "" || conn.UserInfoEndpoint == "" {
		if conn.IssuerURL == "" {
			return nil, errors.New("missing issuer url for discovery")
		}
		discovered, err := s.discoverEndpoints(ctx, conn.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery failed: %w", err)
		}
		conn.TokenEndpoint = discovered.TokenEndpoint
		conn.UserInfoEndpoint = discovered.UserInfoEndpoint
	}

	redirectURL := fmt.Sprintf("%s/t/%s/oidc/callback", s.Config.BaseIssuerURL, tenantID)

	oauth2Config := &oauth2.Config{
		ClientID:     conn.ClientID,
		ClientSecret: conn.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  conn.AuthorizationEndpoint,
			TokenURL: conn.TokenEndpoint,
		},
		RedirectURL: redirectURL,
	}

	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	if conn.UserInfoEndpoint == "" {
		return nil, errors.New("userinfo endpoint is missing")
	}

	// UserInfo Fetch
	client := oauth2Config.Client(ctx, token)
	resp, err := client.Get(conn.UserInfoEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned status: %d", resp.StatusCode)
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode userinfo: %w", err)
	}

	return userInfo, nil
}

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}

func (s *ClientService) discoverEndpoints(ctx context.Context, issuer string) (*oidcDiscovery, error) {
	issuer = strings.TrimRight(issuer, "/")
	configURL := fmt.Sprintf("%s/.well-known/openid-configuration", issuer)

	logger.Log.Info("Discovering OIDC endpoints", zap.String("url", configURL))

	req, err := http.NewRequestWithContext(ctx, "GET", configURL, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}

	var disc oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return nil, err
	}

	return &disc, nil
}
