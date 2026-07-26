package handlers_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSAMLIssuanceObservability drives a real IdP-SSO issuance flow and asserts:
//   - POSITIVE: the use-case boundary log for the issued Response is present and
//     correlated by login_challenge, and records attribute NAMES.
//   - NEGATIVE CONTROL (mandatory hard-constraint guard): a recognisable NameID
//     value and a recognisable attribute value flow into the issued assertion, yet
//     NEITHER appears anywhere in the captured log output.
//
// TEETH for the negative control: temporarily add a value field (e.g.
// zap.String("leak", nameIDValue)) to the "SAML Response issued" log in
// saml_builder_usecase.go — this test then FAILS on the raw subject; remove it and
// it PASSES.
func TestSAMLIssuanceObservability(t *testing.T) {
	env := setupOIDCE2EEnv(t)

	const (
		clientID = "obs-sp"
		entityID = "https://sp.obs.example/metadata"
		acsURL   = "https://sp.obs.example/acs"
		// Recognisable values that must NEVER reach a log line.
		rawSubject   = "NEG-CONTROL-SUBJECT-9f3a2b@example.test"
		rawAttrValue = "NEG-CONTROL-ATTRVALUE-7b21e4"
	)

	createE2ESAMLClient(t, env, clientID, entityID, acsURL, false, false, false, "")
	challenge := startE2EIdPSSO(t, env, buildAuthnRequestXML(entityID, acsURL, ""))

	// Authenticated identity carrying recognisable values as the subject and as an
	// attribute value. These are issued into the assertion during the follow step.
	attrs := map[string]interface{}{
		"identity": map[string]interface{}{
			"attributes": map[string]interface{}{
				"email":              rawAttrValue + "@example.test",
				"name":               rawAttrValue,
				"preferred_username": "obsuser",
			},
			"groups": []string{"engineering"},
			"roles":  []string{"admin"},
		},
		"authentication": map[string]interface{}{"amr": []string{"pwd"}},
	}
	redirectTo := acceptE2ESAMLLoginRaw(t, env, challenge, rawSubject, attrs)

	// Capture the issuance HTTP step, which drives GenerateSAMLResponse and emits
	// the use-case boundary log. The recognisable values (stored at accept time)
	// flow into the issued assertion during exactly this step.
	buf := captureLogger(t)
	resp := followE2ERedirect(t, env, redirectTo)
	require.Equal(t, http.StatusOK, resp.Code, "issuance step must produce a SAML Response")

	logs := buf.String()
	require.NotEmpty(t, logs, "expected the issuance step to emit log output")

	// POSITIVE: correlated, structured boundary log.
	require.Contains(t, logs, "saml.response.issued", "expected the issuance boundary event")
	require.Contains(t, logs, "login_challenge_prefix", "issuance log must be correlated by login_challenge")
	require.Contains(t, logs, "attribute_names", "issuance log must record attribute names")

	// NEGATIVE CONTROL: no raw value of any kind reaches the logs.
	require.NotContains(t, logs, rawSubject, "raw NameID/subject value must not appear in any log")
	require.NotContains(t, logs, rawAttrValue, "raw attribute value must not appear in any log")
}
