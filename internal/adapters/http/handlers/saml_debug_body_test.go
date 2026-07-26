package handlers_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/Shyntr/shyntr/pkg/logger"
)

// captureDebugLogger swaps logger.Log for a Debug-level buffer-backed core so the
// gated Debug body logs are observable, and restores it on cleanup.
func captureDebugLogger(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zapcore.EncoderConfig{
			MessageKey:  "msg",
			LevelKey:    "level",
			EncodeLevel: zapcore.LowercaseLevelEncoder,
		}),
		zapcore.AddSync(buf),
		zapcore.DebugLevel,
	)
	prev := logger.Log
	logger.Log = zap.New(core)
	t.Cleanup(func() { logger.Log = prev })
	return buf
}

// TestSAMLDebugBodies_DefaultOff guards the default: on a normal inbound flow with
// the flag at its default (false), no raw body / UNSAFE_DEBUG line is ever logged.
//
// TEETH (gate): remove the flag check in logWireMessageBody — this test then FAILS
// because a body is logged with the flag off; restore it and it PASSES.
func TestSAMLDebugBodies_DefaultOff(t *testing.T) {
	env := setupOIDCE2EEnv(t)
	require.False(t, env.cfg.SAMLDebugLogMessageBodies, "flag must default to false")

	idp := newFixtureIdP(t, "https://idp.debugoff.example/meta")
	const connID = "debugoff-conn"
	registerFixtureIdPConnection(t, env, connID, idp)

	respB64 := buildInboundSAMLResponse(t, idp, defaultInboundParams(env, idp))

	buf := captureDebugLogger(t)
	driveInboundACS(t, env, connID, respB64)

	logs := buf.String()
	require.NotContains(t, logs, "UNSAFE_DEBUG", "no body must be logged when the flag is off")
	require.NotContains(t, logs, "saml.debug.message_body", "no body event when the flag is off")
	require.NotContains(t, logs, "message_body", "no raw body field when the flag is off")
}

// TestSAMLDebugBodies_NegativeControl is the point of this work order. With the
// flag ON, it drives an issuance whose Response carries an EncryptedAssertion (the
// SP is configured for assertion encryption) whose plaintext holds a recognisable
// marker, and asserts:
//
//	a. the raw on-the-wire body IS logged (flag works), including the
//	   EncryptedAssertion as CIPHERTEXT;
//	b. the DECRYPTED assertion plaintext marker is ABSENT;
//	c. the SP private key material is ABSENT;
//	d. a recognisable client secret is ABSENT.
//
// TEETH (hygiene): temporarily add, in GenerateSAMLResponse just before
// encryptAssertionBytes, `s.logWireMessageBody(ctx, "PLAINTEXT", assertBytesToEncrypt)`
// — assertion (b) then FAILS on the marker; remove it and it PASSES.
func TestSAMLDebugBodies_NegativeControl(t *testing.T) {
	const (
		decryptedMarker = "DECRYPTED-PLAINTEXT-MARKER-a91f7c"
		clientSecret    = "CLIENT-SECRET-MARKER-6b02de"
	)

	env := setupOIDCE2EEnv(t)
	// Enable the flag on the same config the use case holds by pointer.
	env.cfg.SAMLDebugLogMessageBodies = true

	// An SP with assertion encryption: Shyntr encrypts to spEnc's PUBLIC cert. The
	// matching PRIVATE key stays in the test and is NEVER given to Shyntr, so if it
	// ever appeared in a log that would be a genuine leak.
	spEnc := newFixtureIdP(t, "https://sp.enc.example/meta")
	spPrivPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(spEnc.key),
	})

	const (
		clientID = "enc-sp"
		entityID = "https://sp.enc.example/meta"
		acsURL   = "https://sp.enc.example/acs"
	)
	// signResponse=false, signAssertion=false, encryptAssertion=true, enc cert = spEnc's public cert.
	createE2ESAMLClient(t, env, clientID, entityID, acsURL, false, false, true, spEnc.certPEM)

	challenge := startE2EIdPSSO(t, env, buildAuthnRequestXML(entityID, acsURL, ""))
	// The marker rides as an attribute value; it ends up inside the (encrypted) assertion.
	attrs := map[string]interface{}{
		"identity": map[string]interface{}{
			"attributes": map[string]interface{}{
				"name":               decryptedMarker,
				"preferred_username": "encuser",
			},
		},
		"authentication": map[string]interface{}{"amr": []string{"pwd"}},
	}
	redirectTo := acceptE2ESAMLLoginRaw(t, env, challenge, "enc-subject@example.test", attrs)

	buf := captureDebugLogger(t)
	// Prove the sensitive markers ARE loggable, then reset, so their later absence
	// is a real assertion rather than a vacuous one.
	logger.Log.Debug("scaffolding markers",
		zap.String("_priv", string(spPrivPEM)),
		zap.String("_secret", clientSecret))
	require.Contains(t, buf.String(), clientSecret)
	require.Contains(t, buf.String(), "PRIVATE KEY")
	buf.Reset()

	resp := followE2ERedirect(t, env, redirectTo)
	require.Equal(t, http.StatusOK, resp.Code, "issuance must succeed so the outbound body is logged")
	logs := buf.String()

	// (a) wire body logged, including EncryptedAssertion ciphertext.
	require.Contains(t, logs, "UNSAFE_DEBUG", "flag on: the raw body must be logged")
	require.Contains(t, logs, "saml.debug.message_body")
	require.Contains(t, logs, "EncryptedAssertion", "the logged wire body must contain the EncryptedAssertion element")
	require.Contains(t, logs, "CipherValue", "the logged wire body must contain the ciphertext")

	// (b) decrypted plaintext marker never logged.
	require.NotContains(t, logs, decryptedMarker, "decrypted assertion plaintext must never be logged")
	// (c) SP private key material never logged.
	require.NotContains(t, logs, string(spPrivPEM), "SP private key must never be logged")
	require.NotContains(t, logs, "PRIVATE KEY", "no PEM private key block may be logged")
	// (d) client secret never logged.
	require.NotContains(t, logs, clientSecret, "client secret must never be logged")
}
