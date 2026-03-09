package entity

import (
	"errors"
	"time"

	"github.com/go-jose/go-jose/v3"
)

type OAuth2Client struct {
	ID                      string              `json:"client_id"`
	TenantID                string              `json:"tenant_id"`
	Name                    string              `json:"name"`
	AppID                   string              `json:"app_id"`
	Secret                  string              `json:"client_secret"`
	RedirectURIs            []string            `json:"redirect_uris"`
	GrantTypes              []string            `json:"grant_types"`
	ResponseTypes           []string            `json:"response_types"`
	ResponseModes           []string            `json:"response_modes"`
	Scopes                  []string            `json:"scopes"`
	Audience                []string            `json:"audience"`
	Public                  bool                `json:"public"`
	TokenEndpointAuthMethod string              `json:"token_endpoint_auth_method"`
	EnforcePKCE             bool                `json:"enforce_pkce"`
	AllowedCORSOrigins      []string            `json:"allowed_cors_origins"`
	PostLogoutRedirectURIs  []string            `json:"post_logout_redirect_uris"`
	JSONWebKeys             *jose.JSONWebKeySet `json:"-"`
	SkipConsent             bool                `json:"skip_consent"`
	SubjectType             string              `json:"subject_type"`
	BackchannelLogoutURI    string              `json:"backchannel_logout_uri"`
	AccessTokenLifespan     string              `json:"access_token_lifespan,omitempty"`
	IDTokenLifespan         string              `json:"id_token_lifespan,omitempty"`
	RefreshTokenLifespan    string              `json:"refresh_token_lifespan,omitempty"`
	CreatedAt               time.Time           `json:"created_at"`
	UpdatedAt               time.Time           `json:"updated_at,omitempty"`
}

func (c *OAuth2Client) Validate() error {
	if c.TenantID == "" {
		return errors.New("tenant_id is required")
	}

	if c.Public {
		if c.Secret != "" {
			return errors.New("public clients cannot have a client_secret")
		}
		if c.TokenEndpointAuthMethod != "none" {
			return errors.New("public clients must use 'none' as token_endpoint_auth_method")
		}
		c.EnforcePKCE = true
	} else {
		if c.Secret == "" {
			return errors.New("confidential clients must have a hashed secret")
		}
	}

	if len(c.RedirectURIs) == 0 {
		return errors.New("at least one redirect_uri is required")
	}

	return nil
}
