package handlers_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// captureLogger swaps the package-global logger.Log for a buffer-backed JSON core
// and returns the buffer. logger.FromGin uses logger.Log as its base, so every
// field the SLO handlers emit lands in the buffer. The original logger is
// restored on test cleanup.
func captureLogger(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zapcore.EncoderConfig{
			MessageKey:  "msg",
			LevelKey:    "level",
			EncodeLevel: zapcore.LowercaseLevelEncoder,
		}),
		zapcore.AddSync(buf),
		zapcore.InfoLevel,
	)
	prev := logger.Log
	logger.Log = zap.New(core)
	t.Cleanup(func() { logger.Log = prev })
	return buf
}

// samlLogoutRequestB64 builds a minimal SAML LogoutRequest (POST binding, not
// DEFLATE-compressed) carrying the given issuer and NameID, base64-encoded as it
// would arrive in a SAMLRequest form field.
func samlLogoutRequestB64(issuer, nameID string) string {
	xml := fmt.Sprintf(
		`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" `+
			`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="slo-hygiene-1" `+
			`Version="2.0" IssueInstant="2026-01-02T03:04:05Z">`+
			`<saml:Issuer>%s</saml:Issuer><saml:NameID>%s</saml:NameID></samlp:LogoutRequest>`,
		issuer, nameID)
	return base64.StdEncoding.EncodeToString([]byte(xml))
}

// TestSAMLSLO_SubjectHashedInLogs proves the two SLO log lines emit the user
// subject (NameID value) as a sha256 hash, never in clear text. Both paths are
// driven through the real HTTP handlers; the assertions read the captured log.
//
// TEETH: reverting the hashForLog wrapping in saml.go makes both subtests fail
// because the raw subject then appears in the log.
func TestSAMLSLO_SubjectHashedInLogs(t *testing.T) {
	// IdP-SLO path (saml.go IDPSLO): an SP LogoutRequest whose subject has no
	// active OAuth session reaches the "session not found" warning at saml.go:813.
	t.Run("idp_slo_session_not_found", func(t *testing.T) {
		env := setupOIDCE2EEnv(t)

		const entityID = "https://sp.slo-hygiene.example/metadata"
		const rawSubject = "alice.idpslo-hygiene@example.test"
		// SP client registered for the LogoutRequest issuer, with an SLO URL and no
		// certificate (so the GET-only signature branch is irrelevant to this POST).
		createSAMLClientFixture(t, env.db, "tenant-a", "saml-slo-client", entityID,
			"https://sp.slo-hygiene.example/slo", "")

		buf := captureLogger(t)

		form := url.Values{}
		form.Set("SAMLRequest", samlLogoutRequestB64(entityID, rawSubject))
		serveRequest(t, env.router, http.MethodPost, "/t/tenant-a/saml/idp/slo",
			strings.NewReader(form.Encode()),
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"})

		assertSubjectHashed(t, buf.String(), rawSubject)
	})

	// SP-SLO path (saml.go SPSLO): an IdP LogoutRequest with a known connection and
	// a NameID reaches the "sessions destroyed" info line at saml.go:1048.
	t.Run("sp_slo_sessions_destroyed", func(t *testing.T) {
		env := setupOIDCE2EEnv(t)

		const idpEntityID = "https://idp.slo-hygiene.example/metadata"
		const rawSubject = "bob.spslo-hygiene@example.test"
		// SAML connection whose IdP entity ID matches the LogoutRequest issuer.
		createSAMLConnectionFixture(t, env.db, "tenant-a", "saml-slo-conn", idpEntityID,
			"https://idp.slo-hygiene.example/sso", "")

		buf := captureLogger(t)

		form := url.Values{}
		form.Set("SAMLRequest", samlLogoutRequestB64(idpEntityID, rawSubject))
		serveRequest(t, env.router, http.MethodPost, "/t/tenant-a/saml/sp/slo",
			strings.NewReader(form.Encode()),
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"})

		assertSubjectHashed(t, buf.String(), rawSubject)
	})
}

// assertSubjectHashed verifies the log captured a hashed subject and never the
// raw value. The hash is computed independently here (sha256 hex) to match the
// production hashForLog helper and to prove determinism.
func assertSubjectHashed(t *testing.T, logOutput, rawSubject string) {
	t.Helper()
	require.NotEmpty(t, logOutput, "expected the SLO handler to emit a log line")

	sum := sha256.Sum256([]byte(rawSubject))
	expectedHash := hex.EncodeToString(sum[:])

	require.NotContains(t, logOutput, rawSubject,
		"raw NameID/subject must never appear in the log")
	require.Contains(t, logOutput, "subject_sha256",
		"expected the hashed subject field to be present")
	require.Contains(t, logOutput, expectedHash,
		"expected the deterministic sha256 hash of the subject in the log")
}
