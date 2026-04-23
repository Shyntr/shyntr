package utils_test

import (
	"testing"

	"github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectNormalizedIdentityClaims_CanonicalFields(t *testing.T) {
	t.Parallel()

	req := &model.LoginRequest{
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
					"department": "Engineering"
				},
				"groups": ["engineering"],
				"roles": ["admin"]
			},
			"authentication": {
				"amr": ["pwd"],
				"acr": "urn:shyntr:loa:1"
			}
		}`),
	}

	claims, ok := utils.ProjectNormalizedIdentityClaims(req)
	require.True(t, ok)
	require.Equal(t, "ext:12345", claims["sub"])
	require.Equal(t, "alice", claims["preferred_username"])
	require.Equal(t, "alice@example.com", claims["email"])
	require.Equal(t, true, claims["email_verified"])
	require.Equal(t, "Alice Doe", claims["name"])
	require.Equal(t, "Alice", claims["given_name"])
	require.Equal(t, "Doe", claims["family_name"])
	require.Equal(t, []string{"engineering"}, claims["groups"])
	require.Equal(t, []string{"admin"}, claims["roles"])
	require.Equal(t, []string{"pwd"}, claims["amr"])
	require.Equal(t, "urn:shyntr:loa:1", claims["acr"])
	assert.NotContains(t, claims, "department")
}

func TestProjectNormalizedIdentityClaims_IgnoresMalformedOptionalFields(t *testing.T) {
	t.Parallel()

	req := &model.LoginRequest{
		Subject: "ext:12345",
		Context: []byte(`{
			"identity": {
				"attributes": {
					"email": "alice@example.com",
					"email_verified": "true"
				}
			}
		}`),
	}

	claims, ok := utils.ProjectNormalizedIdentityClaims(req)
	require.True(t, ok)
	require.Equal(t, "ext:12345", claims["sub"])
	require.Equal(t, "alice@example.com", claims["email"])
	assert.NotContains(t, claims, "email_verified")
}

func TestProjectNormalizedIdentityClaims_RejectsMalformedCollectionWithoutLeaking(t *testing.T) {
	t.Parallel()

	req := &model.LoginRequest{
		Subject: "ext:12345",
		Context: []byte(`{
			"identity": {
				"attributes": {
					"email": "alice@example.com"
				},
				"groups": "engineering"
			}
		}`),
	}

	claims, ok := utils.ProjectNormalizedIdentityClaims(req)
	require.False(t, ok)
	require.Nil(t, claims)
}
