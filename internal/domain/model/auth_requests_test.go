package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoginRequest_NormalizedContext_ReturnsStoredEnvelope(t *testing.T) {
	t.Parallel()

	contextBytes := []byte(`{
		"identity": {
			"attributes": {
				"preferred_username": "alice",
				"email": "alice@example.com",
				"name": "Alice Doe"
			},
			"groups": ["engineering"],
			"roles": []
		},
		"authentication": {
			"amr": ["pwd"],
			"authenticated_at": "2026-04-23T18:30:00Z"
		}
	}`)

	req := &LoginRequest{Context: contextBytes}
	ctx, ok, err := req.NormalizedContext()
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "alice", ctx.Identity.Attributes["preferred_username"])
	require.Equal(t, []string{"engineering"}, ctx.Identity.Groups)
	require.Equal(t, []string{"pwd"}, ctx.Authentication.AMR)
	require.NotNil(t, ctx.Authentication.AuthenticatedAt)
}

func TestValidateNormalizedLoginContextData_RejectsInvalidEnvelope(t *testing.T) {
	t.Parallel()

	contextData := map[string]interface{}{
		"identity": map[string]interface{}{
			"groups": []interface{}{"engineering", ""},
		},
	}

	err := ValidateNormalizedLoginContextData(contextData)
	require.ErrorContains(t, err, "identity groups must not contain empty values")
}

func TestValidateNormalizedLoginContextData_AllowsLegacyContextWithoutEnvelope(t *testing.T) {
	t.Parallel()

	contextData := map[string]interface{}{
		"email":     "alice@example.com",
		"tenant_id": "tenant-a",
	}

	require.NoError(t, ValidateNormalizedLoginContextData(contextData))
}

func TestValidateNormalizedLoginContextData_RejectsNestedAttributePayload(t *testing.T) {
	t.Parallel()

	var contextData map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(`{
		"identity": {
			"attributes": {
				"email": "alice@example.com",
				"raw_profile": {"department": "engineering"}
			}
		}
	}`), &contextData))

	err := ValidateNormalizedLoginContextData(contextData)
	require.ErrorContains(t, err, `identity attribute "raw_profile" has unsupported value type`)
}
