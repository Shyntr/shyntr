package iam

import (
	"encoding/json"

	"github.com/Shyntr/shyntr/internal/domain/model"
	josev3 "github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v4"
	"github.com/ory/fosite"
)

type ExtendedClient struct {
	*fosite.DefaultClient

	JSONWebKeys *jose.JSONWebKeySet `json:"jwks,omitempty"`

	JwksURI string `json:"jwks_uri,omitempty"`

	IDTokenEncryptedResponseAlg string `json:"id_token_encrypted_response_alg,omitempty"`

	IDTokenEncryptedResponseEnc string `json:"id_token_encrypted_response_enc,omitempty"`

	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`

	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	ResponseModes []fosite.ResponseModeType
}

var _ fosite.Client = (*ExtendedClient)(nil)
var _ fosite.OpenIDConnectClient = (*ExtendedClient)(nil)

func (c *ExtendedClient) GetJSONWebKeys() *josev3.JSONWebKeySet {
	if c.JSONWebKeys == nil {
		return nil
	}

	b, err := json.Marshal(c.JSONWebKeys)
	if err != nil {
		return nil
	}

	var v3jwks josev3.JSONWebKeySet
	if err := json.Unmarshal(b, &v3jwks); err != nil {
		return nil
	}

	return &v3jwks
}

func (c *ExtendedClient) GetJSONWebKeysURI() string {
	return c.JwksURI
}

func (c *ExtendedClient) GetTokenEndpointAuthSigningAlgorithm() string {
	return "RS256"
}

func (c *ExtendedClient) GetPostLogoutRedirectURIs() []string {
	return c.PostLogoutRedirectURIs
}

func (c *ExtendedClient) GetTokenEndpointAuthMethod() string {
	if c.TokenEndpointAuthMethod == "" {
		return "client_secret_basic"
	}
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

func (c *ExtendedClient) GetRequestURIs() []string {
	return nil
}

func (c *ExtendedClient) GetRequestObjectSigningAlgorithm() string {
	return "RS256"
}

func toResponseModeTypes(modes []string) []fosite.ResponseModeType {
	result := make([]fosite.ResponseModeType, len(modes))
	for i, m := range modes {
		result[i] = fosite.ResponseModeType(m)
	}
	return result
}

func ToFositeClient(c *model.OAuth2Client) fosite.Client {
	return &ExtendedClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            c.ID,
			Secret:        []byte(c.Secret),
			RedirectURIs:  c.RedirectURIs,
			GrantTypes:    c.GrantTypes,
			ResponseTypes: c.ResponseTypes,
			Scopes:        c.Scopes,
			Audience:      c.Audience,
			Public:        c.Public,
		},
		JSONWebKeys:                 c.JSONWebKeys,
		JwksURI:                     c.JwksURI,
		IDTokenEncryptedResponseAlg: c.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc: c.IDTokenEncryptedResponseEnc,
		PostLogoutRedirectURIs:      c.PostLogoutRedirectURIs,
		TokenEndpointAuthMethod:     c.TokenEndpointAuthMethod,
		ResponseModes:               toResponseModeTypes(c.ResponseModes),
	}
}
