package usecase

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/domain/model"
	jose "github.com/go-jose/go-jose/v4"
)

// fakeKeyManager is an in-memory KeyManager for GetIdentityProvider tests. Only
// GetActiveKeys is exercised; the remaining interface methods satisfy the
// contract and are never called here. It never touches the database.
type fakeKeyManager struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate // may be nil to exercise the fallback path
}

func (f *fakeKeyManager) GetActivePrivateKey(ctx context.Context, use string) (*rsa.PrivateKey, string, error) {
	return f.key, "test-kid", nil
}

func (f *fakeKeyManager) GetDecryptionKeys(ctx context.Context) (map[string]*rsa.PrivateKey, error) {
	return nil, nil
}

func (f *fakeKeyManager) GetPublicJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	return nil, nil
}

func (f *fakeKeyManager) GetActiveKeys(ctx context.Context, use string) (*rsa.PrivateKey, *x509.Certificate, string, error) {
	return f.key, f.cert, "test-kid", nil
}

func (f *fakeKeyManager) RotateKeys(ctx context.Context) error { return nil }

func (f *fakeKeyManager) ImportKey(ctx context.Context, use string, privKey *rsa.PrivateKey, certPEM []byte) (*model.CryptoKey, error) {
	return nil, nil
}

func newStoredCert(t *testing.T, key *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	template := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "Stored Signing Cert"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create stored cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse stored cert: %v", err)
	}
	return cert
}

func newIdPBuilder(km *fakeKeyManager) *samlBuilderUseCase {
	return &samlBuilderUseCase{
		KeyMgr: km,
		Config: &config.Config{BaseIssuerURL: "https://idp.example.test"},
	}
}

// (a) The IdentityProvider certificate is the stored certificate (by DER bytes),
// and (d) its Key is the key the KeyManager returned.
func TestGetIdentityProvider_UsesStoredCertificateAndKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	stored := newStoredCert(t, key)
	builder := newIdPBuilder(&fakeKeyManager{key: key, cert: stored})

	idp, err := builder.GetIdentityProvider(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("GetIdentityProvider: %v", err)
	}

	if idp.Certificate == nil {
		t.Fatal("IdentityProvider.Certificate is nil")
	}
	if !bytesEqual(idp.Certificate.Raw, stored.Raw) {
		t.Fatalf("IdentityProvider.Certificate DER does not match the stored certificate")
	}
	if idp.Key != key {
		t.Fatalf("IdentityProvider.Key is not the KeyManager's key")
	}
}

// (b) Two consecutive calls return the SAME certificate DER. This captures the
// defect directly: before the fix each call minted a fresh self-signed cert.
func TestGetIdentityProvider_CertificateIsStableAcrossCalls(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	stored := newStoredCert(t, key)
	builder := newIdPBuilder(&fakeKeyManager{key: key, cert: stored})

	first, err := builder.GetIdentityProvider(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("first GetIdentityProvider: %v", err)
	}
	second, err := builder.GetIdentityProvider(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("second GetIdentityProvider: %v", err)
	}

	if !bytesEqual(first.Certificate.Raw, second.Certificate.Raw) {
		t.Fatalf("certificate DER differs between two GetIdentityProvider calls; it must be stable")
	}
}

// (c) With no stored certificate the call still succeeds and yields a usable
// certificate whose public key matches the private key.
func TestGetIdentityProvider_FallsBackWhenNoStoredCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	builder := newIdPBuilder(&fakeKeyManager{key: key, cert: nil})

	idp, err := builder.GetIdentityProvider(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("GetIdentityProvider (fallback): %v", err)
	}
	if idp.Certificate == nil {
		t.Fatal("fallback IdentityProvider.Certificate is nil")
	}
	pub, ok := idp.Certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("fallback certificate public key is not RSA")
	}
	if pub.N.Cmp(key.PublicKey.N) != 0 || pub.E != key.PublicKey.E {
		t.Fatalf("fallback certificate public key does not match the signing key")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
