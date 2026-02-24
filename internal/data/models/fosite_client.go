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

	ResponseModes []fosite.ResponseModeType
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

func (c *ExtendedClient) GetResponseModes() []fosite.ResponseModeType {
	if len(c.ResponseModes) == 0 {
		return []fosite.ResponseModeType{
			fosite.ResponseModeQuery,
			fosite.ResponseModeFragment,
			fosite.ResponseModeFormPost,
		}
	}
	return c.ResponseModes
}
