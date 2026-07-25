package handlers_test

// SHA-1 inbound signature policy — proven end to end through the REAL ACS endpoint.
//
// The SHA-1 policy (commit 9c2dc23) rejects SHA-1 on the embedded / POST-binding
// path by wiring signatureAlgorithmVerifier into crewjam's SignatureVerifier hook.
// Until now that ACS path was verified only through crewjam's documented contract
// and unit tests against verifyPostSignature; it was never observed end to end at
// the HTTP boundary. These tests close that debt using the S27 inbound ACS harness.
//
// P1 (a valid SHA-256 Response is accepted) is already proven by
// TestSAMLInboundACS_ValidSHA256ResponseIsAccepted in the harness file; it is
// referenced, not duplicated.
//
// HOW THE REJECTION REASON IS ESTABLISHED AS THE ALGORITHM (not something incidental)
// The ACS handler deliberately does NOT surface the T1-5 diagnostic category
// (signature_algorithm_rejected_sha1) to the client: writeProtocolError sends the
// generic code "invalid_saml_response" in the body/header and logs the specific
// category via LogOnlyError. So the category is not observable at the HTTP
// boundary. Instead the algorithm is isolated as the sole cause the only way that
// is airtight over HTTP: the SAME SHA-1 Response bytes are driven through two
// environments that differ in exactly one variable — SAML_ALLOW_SHA1_SIGNATURES.
// Under the default (false) the bytes are REJECTED; with the flag enabled the
// identical bytes are ACCEPTED. If the rejection were caused by trust, parsing,
// timestamps, audience, destination, or recipient, flipping only the SHA-1 policy
// could not turn rejection into acceptance. P3's acceptance therefore doubles as
// the "policy bypassed → same Response accepted" control the work order asks for.
//
// DIGEST vs SIGNATURE (the K6 mixed case) is intentionally NOT attempted here: the
// harness signs with a single goxmldsig SigningContext.Hash, which drives BOTH the
// SignatureMethod and every Reference DigestMethod, so it cannot emit a SHA-256
// signature over a SHA-1 digest. The work order forbids modifying the harness, so
// this case is skipped rather than faked. That mixed case is already covered at the
// policy layer, where checkEmbeddedSignatureAlgorithms inspects every
// Reference/DigestMethod independently of the SignatureMethod (saml_signature_policy_test.go).

import (
	"crypto"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSAMLInboundACS_SHA1RejectedByDefaultAcceptedWhenEnabled is the teeth for the
// inbound SHA-1 policy. It builds ONE SHA-1-signed Response from a fixture external
// IdP and drives those identical bytes through the real ACS endpoint twice:
//
//	P2 — default policy (SAML_ALLOW_SHA1_SIGNATURES false)  -> REJECTED (401)
//	P3 — same bytes, SAML_ALLOW_SHA1_SIGNATURES enabled     -> ACCEPTED (302)
//
// The only variable that changes between the two drives is the policy flag, so the
// flip from rejection to acceptance isolates the SHA-1 algorithm as the cause.
func TestSAMLInboundACS_SHA1RejectedByDefaultAcceptedWhenEnabled(t *testing.T) {
	const connectionID = "conn-inbound-sha1"

	// One fixture IdP and one SHA-1-signed Response, reused verbatim for both
	// drives so the Response bytes are provably identical across the comparison.
	idp := newFixtureIdP(t, "https://idp.example.test/inbound-sha1")

	// Parameters come from a throwaway env, but every field they depend on
	// (BaseIssuerURL, DefaultTenantID) is identical across envs, so the same bytes
	// are valid inbound Responses for both. Only the signature algorithm differs
	// from the accepted-by-P1 case: SHA-1 instead of SHA-256.
	paramEnv := setupOIDCE2EEnv(t)
	params := defaultInboundParams(paramEnv, idp)
	params.subject = "sha1-external-user@example.test"
	params.attributes = map[string]string{"email": "sha1-external-user@example.test"}
	params.hash = crypto.SHA1
	sha1Response := buildInboundSAMLResponse(t, idp, params)

	resumePath := fmt.Sprintf("/t/%s/saml/resume", paramEnv.cfg.DefaultTenantID)

	// --- P2: default policy REJECTS the SHA-1 Response ------------------------
	strictEnv := setupOIDCE2EEnv(t)
	require.False(t, strictEnv.cfg.SAMLAllowSHA1Signatures,
		"precondition: the default policy must have SHA-1 disabled")
	registerFixtureIdPConnection(t, strictEnv, connectionID, idp)

	rejected := driveInboundACS(t, strictEnv, connectionID, sha1Response)

	require.Equalf(t, http.StatusUnauthorized, rejected.status,
		"under the default policy a SHA-1-signed inbound Response must be rejected at ACS (error_code=%q)", rejected.errorCode)
	require.Equal(t, "invalid_saml_response", rejected.errorCode,
		"rejection must surface the SAML response validation failure code")
	require.Empty(t, rejected.location, "a rejected Response must not resume the login flow")

	// --- P3: SAME bytes, SHA-1 explicitly enabled, ACCEPTS -------------------
	// Fresh env (fresh DB and replay cache) so the identical assertion ID is not
	// a replay; the policy flag is the only thing that differs from strictEnv.
	permissiveEnv := setupOIDCE2EEnv(t)
	permissiveEnv.cfg.SAMLAllowSHA1Signatures = true // SAML_ALLOW_SHA1_SIGNATURES=true
	registerFixtureIdPConnection(t, permissiveEnv, connectionID, idp)

	accepted := driveInboundACS(t, permissiveEnv, connectionID, sha1Response)

	require.Equalf(t, http.StatusFound, accepted.status,
		"with SHA-1 explicitly enabled the identical Response must be accepted at ACS (error_code=%q)", accepted.errorCode)
	require.Contains(t, accepted.location, resumePath,
		"acceptance must resume the originating login flow")
	require.Empty(t, accepted.errorCode, "an accepted Response must not set a failure category")

	// The two drives used byte-identical Responses and identical trust; the sole
	// difference was the SHA-1 policy flag. Rejection flipping to acceptance on
	// that single change proves the rejection reason is the SHA-1 algorithm.
}
