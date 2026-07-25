package handlers_test

// InResponseTo / AllowIDPInitiated — CHARACTERIZATION of a KNOWN DEFERRED GAP (S1).
//
// These two tests pin TODAY'S permissive behaviour so it is documented,
// test-guarded, and impossible to close silently. They do NOT endorse it.
//
// THE GAP (S1): Shyntr's SP is built with crewjam AllowIDPInitiated=true and
// enforces InResponseTo nowhere. Consequently:
//   - an IdP-initiated Response carrying NO InResponseTo is accepted (Q1), and
//   - a Response carrying an arbitrary InResponseTo — an ID Shyntr never issued —
//     is accepted, because the value is never checked (Q2).
// crewjam validateRequestID short-circuits to valid whenever AllowIDPInitiated is
// set (service_provider.go), so both the Response-level InResponseTo and the
// assertion SubjectConfirmation InResponseTo are ignored today.
//
// THE FIX IS DEFERRED to the Spiral 7 partner window: making AllowIDPInitiated a
// per-client flag defaulting to false and requiring InResponseTo on SP-initiated
// flows is a behavioural change that affects partners. It is deliberately NOT done
// here — this is characterization only, and nothing accepted today is made to
// reject.
//
// WHEN THE FIX LANDS, INVERT THESE TESTS — DO NOT DELETE THEM. Each will start
// failing (the Response will be rejected); at that point re-express it as a real
// assertion of the secure behaviour (rejection) and rename it, so the guard
// survives as a positive test rather than being removed.

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// s1InversionNote is embedded in every assertion message so a future reader who
// sees one of these tests fail understands it is a known deferred gap being
// closed, and must INVERT (not delete) the test.
const s1InversionNote = "KNOWN DEFERRED GAP (S1), fix scheduled for the Spiral 7 partner window: " +
	"this test asserts CURRENT permissive behaviour — Shyntr accepts this Response because " +
	"AllowIDPInitiated is true and InResponseTo is enforced nowhere. If it FAILS, the gap has " +
	"been closed (InResponseTo now enforced / IdP-initiated gated behind a per-client flag). " +
	"That is the intended end state: INVERT this test into a real assertion of rejection and " +
	"rename it. DO NOT delete it."

// decodeSAMLResponseForAssert base64-decodes a built SAMLResponse so a test can
// characterize the on-the-wire InResponseTo state. It returns the raw XML string;
// callers assert on structural presence/absence only, never logging the body.
func decodeSAMLResponseForAssert(t *testing.T, samlResponseB64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(samlResponseB64)
	require.NoError(t, err)
	return string(raw)
}

// TestSAMLInboundACS_KnownGap_S1_IdPInitiatedNoInResponseToAccepted characterizes
// Q1: an IdP-initiated Response — valid SHA-256 signature, trusted connection, and
// NO InResponseTo anywhere — is ACCEPTED today.
//
// KNOWN DEFERRED GAP (S1). See the file header and s1InversionNote. When
// IdP-initiated is later gated behind a per-client flag defaulting to false, this
// test must be INVERTED (assert rejection) and renamed, never deleted.
func TestSAMLInboundACS_KnownGap_S1_IdPInitiatedNoInResponseToAccepted(t *testing.T) {
	env := setupOIDCE2EEnv(t)

	idp := newFixtureIdP(t, "https://idp.example.test/s1-idp-initiated")
	const connectionID = "conn-s1-idp-initiated"
	registerFixtureIdPConnection(t, env, connectionID, idp)

	// Default params carry no InResponseTo — the pure IdP-initiated shape.
	params := defaultInboundParams(env, idp)
	params.subject = "idp-initiated-user@example.test"
	require.Empty(t, params.inResponseTo, "Q1 fixture must be IdP-initiated: no InResponseTo")

	responseB64 := buildInboundSAMLResponse(t, idp, params)

	// Pin the IdP-initiated nature on the wire: the Response carries no
	// InResponseTo correlation to any request Shyntr issued.
	require.NotContains(t, decodeSAMLResponseForAssert(t, responseB64), "InResponseTo",
		"Q1 fixture must contain no InResponseTo attribute anywhere in the Response")

	outcome := driveInboundACS(t, env, connectionID, responseB64)

	// CURRENT behaviour: accepted. This is the gap.
	require.Equalf(t, http.StatusFound, outcome.status,
		"%s\n(an IdP-initiated Response with no InResponseTo is accepted today; error_code=%q)",
		s1InversionNote, outcome.errorCode)
	require.Containsf(t, outcome.location, fmt.Sprintf("/t/%s/saml/resume", env.cfg.DefaultTenantID),
		"%s\n(acceptance resumes the login flow today)", s1InversionNote)
	require.Emptyf(t, outcome.errorCode, "%s\n(no failure category is set on acceptance today)", s1InversionNote)
}

// TestSAMLInboundACS_KnownGap_S1_ArbitraryInResponseToAccepted characterizes Q2 at
// the strength the harness can express: a Response whose InResponseTo references an
// ID Shyntr NEVER issued is ACCEPTED today, because the value is never validated.
//
// STRENGTH NOTE (reported in full in the work-order output): this is the weaker,
// still-real form of Q2 — "an arbitrary InResponseTo value is accepted regardless
// of that value." It is NOT the stronger "genuine pending-request mismatch"
// (Shyntr issued request R, Response references R'≠R), because the S27 harness's
// driveInboundACS creates the login request with an empty SAMLRequestID and offers
// no parameter to set one, so no tracked pending request exists to mismatch
// against. Expressing the stronger form needs a new harness capability (a
// request-ID parameter on driveInboundACS); it is reported, not built inline.
// Crucially, the stronger form would assert the identical acceptance: crewjam's
// validateRequestID marks the request valid unconditionally while
// AllowIDPInitiated is true, so even a genuine mismatch is accepted today.
//
// KNOWN DEFERRED GAP (S1). See the file header and s1InversionNote. When
// InResponseTo is later enforced on SP-initiated flows, this test must be INVERTED
// (assert rejection of a mismatched/unknown InResponseTo) and renamed, never
// deleted.
func TestSAMLInboundACS_KnownGap_S1_ArbitraryInResponseToAccepted(t *testing.T) {
	env := setupOIDCE2EEnv(t)

	idp := newFixtureIdP(t, "https://idp.example.test/s1-arbitrary-inresponseto")
	const connectionID = "conn-s1-arbitrary-inresponseto"
	registerFixtureIdPConnection(t, env, connectionID, idp)

	// An InResponseTo value that references an ID Shyntr never issued.
	const neverIssuedRequestID = "_id-shyntr-never-issued-000000000000"
	params := defaultInboundParams(env, idp)
	params.subject = "mismatched-inresponseto-user@example.test"
	params.inResponseTo = neverIssuedRequestID

	responseB64 := buildInboundSAMLResponse(t, idp, params)

	// Pin that the bogus InResponseTo is actually present on the wire, so the
	// test proves the value is IGNORED rather than absent.
	require.Contains(t, decodeSAMLResponseForAssert(t, responseB64), neverIssuedRequestID,
		"Q2 fixture must carry the never-issued InResponseTo value in the Response")

	outcome := driveInboundACS(t, env, connectionID, responseB64)

	// CURRENT behaviour: accepted despite the unknown InResponseTo. This is the gap.
	require.Equalf(t, http.StatusFound, outcome.status,
		"%s\n(a Response whose InResponseTo references an ID Shyntr never issued is accepted today; error_code=%q)",
		s1InversionNote, outcome.errorCode)
	require.Containsf(t, outcome.location, fmt.Sprintf("/t/%s/saml/resume", env.cfg.DefaultTenantID),
		"%s\n(acceptance resumes the login flow today)", s1InversionNote)
	require.Emptyf(t, outcome.errorCode, "%s\n(no failure category is set on acceptance today)", s1InversionNote)

	// Defensive: the never-issued ID must not have leaked into the handler's
	// client-facing output on the pass path.
	require.NotContains(t, outcome.body, neverIssuedRequestID,
		"the InResponseTo value must not appear in the handler's response body")
}
