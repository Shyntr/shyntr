package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/data/repository"
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

	if oauth2Config.Endpoint.AuthURL == "" || oauth2Config.Endpoint.TokenURL == "" {
		// TODO: Implement OIDC Discovery using conn.IssuerURL
		return "", errors.New("authorization endpoints are missing and discovery is not implemented yet")
	}

	state := fmt.Sprintf("%s|%s", loginChallenge, connectionID)

	return oauth2Config.AuthCodeURL(state), nil
}

func (s *ClientService) ExchangeAndUserInfo(ctx context.Context, tenantID, code, connectionID string) (map[string]interface{}, error) {
	conn, err := s.Repo.GetConnection(ctx, connectionID)
	if err != nil {
		return nil, fmt.Errorf("connection not found: %w", err)
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
