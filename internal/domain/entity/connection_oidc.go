package entity

import (
	"errors"
	"time"
)

type OIDCConnection struct {
	ID                    string                          `json:"id"`
	TenantID              string                          `json:"tenant_id"`
	Name                  string                          `json:"name"`
	IssuerURL             string                          `json:"issuer_url"`
	ClientID              string                          `json:"client_id"`
	ClientSecret          string                          `json:"client_secret"`
	AuthorizationEndpoint string                          `json:"authorization_endpoint"`
	TokenEndpoint         string                          `json:"token_endpoint"`
	UserInfoEndpoint      string                          `json:"userinfo_endpoint"`
	JWKSURI               string                          `json:"jwks_uri"`
	EndSessionEndpoint    string                          `json:"end_session_endpoint"`
	Scopes                []string                        `json:"scopes"`
	AttributeMapping      map[string]AttributeMappingRule `json:"attribute_mapping"`
	Active                bool                            `json:"active"`
	CreatedAt             time.Time                       `json:"created_at"`
	UpdatedAt             time.Time                       `json:"updated_at,omitempty"`
}

func (c *OIDCConnection) Validate() error {
	if c.TenantID == "" {
		return errors.New("tenant_id is required")
	}
	if c.IssuerURL == "" {
		return errors.New("issuer_url is required")
	}
	if c.ClientID == "" {
		return errors.New("client_id is required for OIDC connections")
	}
	return nil
}
