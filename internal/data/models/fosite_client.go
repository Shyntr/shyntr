package models

import (
	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
)

type ExtendedClient struct {
	*fosite.DefaultClient

	JSONWebKeys *jose.JSONWebKeySet `json:"jwks,omitempty"`

	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`

	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
}

func (c *ExtendedClient) GetJSONWebKeys() *jose.JSONWebKeySet {
	return c.JSONWebKeys
}

func (c *ExtendedClient) GetPostLogoutRedirectURIs() []string {
	return c.PostLogoutRedirectURIs
}

func (c *ExtendedClient) GetTokenEndpointAuthMethod() string {
	return c.TokenEndpointAuthMethod
}
