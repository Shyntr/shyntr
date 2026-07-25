package utils_test

// S21 — GetActiveKeys must not silently swallow a stored-certificate parse
// failure. When CertData is malformed, the returned certificate is nil and the
// caller (post-D3) falls back to a transient self-signed certificate under the
// same identity. That substitution must NEVER be silent: this test drives the real
// DefaultKeyManager with a controllable store and asserts the failure is surfaced
// as a loud Error log naming the key id — and that no certificate bytes leak.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/model"
	appcrypto "github.com/Shyntr/shyntr/pkg/crypto"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// testAppSecret is a 32-byte AES-256 key for encrypting stored key material in
// tests. Not a real secret.
const testAppSecret = "12345678901234567890123456789012"

// stubKeyRepo is a controllable port.CryptoKeyRepository for KeyManager tests.
// GetActiveKey returns `active` (or ErrKeyNotFound when nil); Save captures every
// saved key and promotes an ACTIVE one to `active` so a generate-on-miss flow can
// read back what it just provisioned; GetKeysByStates returns `byStates`.
type stubKeyRepo struct {
	active   *model.CryptoKey
	byStates []*model.CryptoKey
	saved    []*model.CryptoKey
}

func (r *stubKeyRepo) GetActiveKey(_ context.Context, _ string) (*model.CryptoKey, error) {
	if r.active == nil {
		return nil, port.ErrKeyNotFound
	}
	return r.active, nil
}

func (r *stubKeyRepo) Save(_ context.Context, key *model.CryptoKey) error {
	r.saved = append(r.saved, key)
	if key.State == model.KeyStateActive {
		r.active = key
	}
	return nil
}

func (r *stubKeyRepo) GetKeysByStates(_ context.Context, _ string, _ []model.KeyState) ([]*model.CryptoKey, error) {
	return r.byStates, nil
}

func (r *stubKeyRepo) DeleteKey(_ context.Context, _ string) error { return nil }

// encryptedTestKeyData returns a valid, AppSecret-encrypted PKCS#1 private key so
// GetActivePrivateKey succeeds and the test isolates the certificate parse path.
func encryptedTestKeyData(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	enc, err := appcrypto.EncryptAES(x509.MarshalPKCS1PrivateKey(key), []byte(testAppSecret))
	require.NoError(t, err)
	return []byte(enc)
}

// malformedCertPEM is a well-formed PEM envelope wrapping non-DER bytes, so
// pem.Decode succeeds but x509.ParseCertificate fails — exercising exactly the
// error S21 previously discarded.
func malformedCertPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-valid-der-certificate-bytes")}))
}

// withObservedLogger swaps the global logger for an observer for the duration of
// fn and returns the captured logs. Restores the previous logger afterward.
func withObservedLogger(fn func()) *observer.ObservedLogs {
	core, recorded := observer.New(zap.DebugLevel)
	prev := logger.Log
	logger.Log = zap.New(core)
	defer func() { logger.Log = prev }()
	fn()
	return recorded
}

// TestGetActiveKeys_S21_MalformedCertIsSurfacedNotSwallowed is the S21 teeth. A
// stored certificate that cannot be parsed must produce a nil certificate AND a
// loud Error log naming the key id — never a silent nil that lets the caller
// self-sign under the stored identity.
func TestGetActiveKeys_S21_MalformedCertIsSurfacedNotSwallowed(t *testing.T) {
	const kid = "sig-deadbeef"
	repo := &stubKeyRepo{
		active: &model.CryptoKey{
			ID:        kid,
			Use:       "sig",
			State:     model.KeyStateActive,
			Algorithm: "RS256",
			KeyData:   encryptedTestKeyData(t),
			CertData:  malformedCertPEM(),
		},
	}
	km := utils.NewKeyManager(repo, &config.Config{AppSecret: testAppSecret})

	var (
		privKey *rsa.PrivateKey
		cert    *x509.Certificate
		err     error
	)
	logs := withObservedLogger(func() {
		privKey, cert, _, err = km.GetActiveKeys(context.Background(), "sig")
	})

	// The private key still loads (the key material is valid); only the cert failed.
	require.NoError(t, err)
	require.NotNil(t, privKey, "the valid private key must still be returned")
	require.Nil(t, cert, "a malformed stored certificate must not parse into a certificate")

	// TEETH: the parse failure must be surfaced as a loud Error log that names the
	// key id. Without the fix, the error is discarded and no such log exists.
	parseFailureLogs := logs.FilterMessageSnippet("could not be parsed").All()
	require.NotEmpty(t, parseFailureLogs,
		"a malformed stored certificate must be surfaced by a loud log, not swallowed")

	entry := parseFailureLogs[0]
	require.Equal(t, zap.ErrorLevel, entry.Level, "the parse-failure log must be loud (Error level)")

	fields := entry.ContextMap()
	require.Equal(t, kid, fields["kid"], "the log must name the key id so the identity change is traceable")
	require.Equal(t, "sig", fields["use"])

	// SECURITY: no certificate bytes may appear anywhere in the surfaced log.
	for _, l := range logs.All() {
		require.NotContains(t, l.Message, "not-valid-der-certificate-bytes",
			"the log message must never contain certificate bytes")
		for _, v := range l.ContextMap() {
			require.NotContains(t, toString(v), "not-valid-der-certificate-bytes",
				"log fields must never contain certificate bytes")
		}
	}
}

func toString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
