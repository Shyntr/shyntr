package usecase_test

import (
	"errors"
	"testing"

	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validateOIDCClientRules(c *model.OAuth2Client) error {
	if c.Public {
		if c.Secret != "" {
			return errors.New("public clients cannot have a client_secret")
		}
		if c.TokenEndpointAuthMethod != "none" {
			return errors.New("public clients must use 'none' as token_endpoint_auth_method")
		}
	}
	return nil
}

func TestOIDCClient_ZeroTrust_PublicClientMustNotHaveSecret(t *testing.T) {
	t.Parallel()

	client := &model.OAuth2Client{
		Public: true,
		Secret: "some-leaked-secret",
	}

	err := validateOIDCClientRules(client)
	require.Error(t, err)
	assert.Equal(t, "public clients cannot have a client_secret", err.Error())
}

func TestOIDCClient_ZeroTrust_PublicClientMustUseNoneAuthMethod(t *testing.T) {
	t.Parallel()

	client := &model.OAuth2Client{
		Public:                  true,
		Secret:                  "",
		TokenEndpointAuthMethod: "client_secret_basic",
	}

	err := validateOIDCClientRules(client)
	require.Error(t, err)
	assert.Equal(t, "public clients must use 'none' as token_endpoint_auth_method", err.Error())
}
