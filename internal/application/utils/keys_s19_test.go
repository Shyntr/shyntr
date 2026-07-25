package utils_test

// S19 — a provisioned SAML/JWT signing (and encryption) identity certificate must
// carry NO ExtKeyUsage. The templates previously set ExtKeyUsage{ServerAuth}, which
// is TLS server authentication — semantically wrong for a signing certificate and
// grounds for rejection by a strict verifier that checks EKU. This test asserts
// both provisioning paths (initial generate-on-miss, and rotation's pending-key
// generation) emit a certificate with no ExtKeyUsage. KeyUsage (DigitalSignature)
// is left intact.

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ensureLogger guarantees the package-global logger is non-nil so the key
// provisioning paths (which log) do not nil-panic under test. It never overwrites
// an already-installed logger.
func ensureLogger() {
	if logger.Log == nil {
		logger.Log = zap.NewNop()
	}
}

// parseStoredCert parses a PEM certificate stored in a CryptoKey's CertData.
func parseStoredCert(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block, "stored CertData must be a valid PEM block")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// assertSigningCertEKU asserts a provisioned signing certificate carries no
// ExtKeyUsage at all (and, explicitly, not ServerAuth) while retaining the
// DigitalSignature KeyUsage.
func assertSigningCertEKU(t *testing.T, cert *x509.Certificate, label string) {
	t.Helper()
	require.Emptyf(t, cert.ExtKeyUsage,
		"%s: a signing certificate must carry no ExtKeyUsage (found %v)", label, cert.ExtKeyUsage)
	require.NotContainsf(t, cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth,
		"%s: ServerAuth is TLS server auth and is wrong for a signing certificate", label)
	require.NotZerof(t, cert.KeyUsage&x509.KeyUsageDigitalSignature,
		"%s: the DigitalSignature KeyUsage must be preserved", label)
}

// TestProvisionedSigningCert_S19_NoServerAuthEKU_InitialTemplate is the S19 teeth
// for the primary provisioning template (loadOrGenerateActiveKey): on an empty
// store, GetActiveKeys generates and persists a signing key+certificate, which must
// carry no ExtKeyUsage.
func TestProvisionedSigningCert_S19_NoServerAuthEKU_InitialTemplate(t *testing.T) {
	ensureLogger()
	repo := &stubKeyRepo{active: nil} // empty store -> generate on miss
	km := utils.NewKeyManager(repo, &config.Config{AppSecret: testAppSecret})

	_, cert, _, err := km.GetActiveKeys(context.Background(), "sig")
	require.NoError(t, err)
	require.NotNil(t, cert, "provisioning must yield a certificate")

	assertSigningCertEKU(t, cert, "initial-provisioning template")
}

// TestProvisionedSigningCert_S19_NoServerAuthEKU_RotationTemplate is the S19 teeth
// for the second template (generateKeyInternal), reached via rotation: an ACTIVE
// key past its rotation TTL with no PENDING key makes RotateKeys generate a new
// PENDING signing key+certificate, which must also carry no ExtKeyUsage.
func TestProvisionedSigningCert_S19_NoServerAuthEKU_RotationTemplate(t *testing.T) {
	ensureLogger()
	agedActive := &model.CryptoKey{
		ID:        "sig-aged",
		Use:       "sig",
		State:     model.KeyStateActive,
		Algorithm: "RS256",
		CreatedAt: time.Now().Add(-40 * 24 * time.Hour), // older than RotationActiveTTL (30d)
	}
	repo := &stubKeyRepo{active: agedActive, byStates: []*model.CryptoKey{agedActive}}
	km := utils.NewKeyManager(repo, &config.Config{AppSecret: testAppSecret, AutoKeyRotationEnabled: true})

	require.NoError(t, km.RotateKeys(context.Background()))

	// Rotation must have generated exactly one new PENDING signing key.
	var pending *model.CryptoKey
	for _, k := range repo.saved {
		if k.State == model.KeyStatePending {
			pending = k
			break
		}
	}
	require.NotNil(t, pending, "rotation must generate a PENDING key via the second template")
	require.NotEmpty(t, pending.CertData, "the generated PENDING key must carry a certificate")

	assertSigningCertEKU(t, parseStoredCert(t, pending.CertData), "rotation pending template")
}
