package utils

import (
	"testing"

	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectNormalizedSAMLAttributes(t *testing.T) {
	loginReq := &model.LoginRequest{
		Subject: "ext:12345",
		Context: []byte(`{
			"identity": {
				"attributes": {
					"preferred_username": "alice",
					"email": "alice@example.com",
					"email_verified": true,
					"name": "Alice Doe",
					"given_name": "Alice",
					"family_name": "Doe",
					"locale": "en-US"
				},
				"groups": ["engineering"],
				"roles": ["admin"]
			},
			"authentication": {
				"amr": ["pwd"],
				"acr": "urn:example:acr"
			}
		}`),
	}

	claims, ok := ProjectNormalizedSAMLAttributes(loginReq)
	require.True(t, ok)

	assert.Equal(t, "ext:12345", claims["sub"])
	assert.Equal(t, "alice", claims["preferred_username"])
	assert.Equal(t, "alice@example.com", claims["email"])
	assert.Equal(t, "Alice Doe", claims["name"])
	assert.Equal(t, "Alice", claims["given_name"])
	assert.Equal(t, "Doe", claims["family_name"])
	assert.Equal(t, []string{"engineering"}, claims["groups"])
	assert.Equal(t, []string{"admin"}, claims["roles"])
	assert.NotContains(t, claims, "email_verified")
	assert.NotContains(t, claims, "locale")
	assert.NotContains(t, claims, "amr")
	assert.NotContains(t, claims, "acr")
}

func TestProjectNormalizedSAMLAttributesIgnoresMalformedContext(t *testing.T) {
	loginReq := &model.LoginRequest{
		Subject: "ext:12345",
		Context: []byte(`{
			"identity": {
				"attributes": {
					"email": "alice@example.com"
				},
				"groups": "engineering",
				"roles": ["admin"]
			}
		}`),
	}

	claims, ok := ProjectNormalizedSAMLAttributes(loginReq)
	require.False(t, ok)
	assert.Nil(t, claims)
}
