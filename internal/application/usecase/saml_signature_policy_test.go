// Inbound SAML signature-algorithm policy gate (K1–K6).
//
// FMN Spiral 4 mandates SHA-256. These tests pin that Shyntr REJECTS SHA-1 on
// inbound signatures by default, on both inbound paths, for both the signature and
// the digest algorithm, while an explicit config flag re-enables SHA-1 for legacy
// interop.
//
//   K1  redirect, SHA-256, default          -> verifies
//   K2  redirect, SHA-1, default            -> REJECTED   (teeth)
//   K3  redirect, SHA-1, SHA-1 enabled      -> verifies   (escape hatch)
//   K4  embedded, SHA-256, default          -> verifies
//   K5  embedded, SHA-1 signature, default  -> REJECTED   (teeth)
//   K6  embedded, SHA-256 sig / SHA-1 digest, default -> REJECTED (teeth)
//
// The redirect helpers (redirectTestKey, signedRedirectQuery, redirectRequest,
// redirectStr, redirectAlg* consts, sampleSAMLRequest, exoticRelay) are defined in
// saml_redirect_signature_test.go (same package) and reused here.
package usecase

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
	"github.com/stretchr/testify/require"
)

func strictPolicyUseCase() *samlBuilderUseCase {
	return &samlBuilderUseCase{Config: &config.Config{SAMLAllowSHA1Signatures: false}}
}

func sha1EnabledUseCase() *samlBuilderUseCase {
	return &samlBuilderUseCase{Config: &config.Config{SAMLAllowSHA1Signatures: true}}
}

// ---- Redirect binding (Path 1) ---------------------------------------------

// K1: a SHA-256 redirect signature verifies under the default (strict) policy.
func TestSAMLSigPolicy_K1_RedirectSHA256DefaultVerifies(t *testing.T) {
	key, certPEM := redirectTestKey(t)
	raw := signedRedirectQuery(t, key, redirectAlgSHA256, "SAMLRequest", sampleSAMLRequest, redirectStr(exoticRelay))
	require.NoError(t, strictPolicyUseCase().VerifyInboundRedirectSignature(redirectRequest(raw), certPEM),
		"SHA-256 redirect signature must verify under the default policy")
}

// K2 — TEETH. A SHA-1 redirect signature is rejected under the default policy,
// even though the signature is cryptographically valid.
func TestSAMLSigPolicy_K2_RedirectSHA1DefaultRejected(t *testing.T) {
	key, certPEM := redirectTestKey(t)
	raw := signedRedirectQuery(t, key, redirectAlgSHA1, "SAMLRequest", sampleSAMLRequest, redirectStr(exoticRelay))
	err := strictPolicyUseCase().VerifyInboundRedirectSignature(redirectRequest(raw), certPEM)
	require.ErrorIs(t, err, errSHA1SignatureDisabled,
		"SHA-1 redirect signature must be rejected by policy under the default")
}

// K3: with SHA-1 explicitly enabled, a valid SHA-1 redirect signature verifies —
// proving the escape hatch works, not just that the default is strict.
func TestSAMLSigPolicy_K3_RedirectSHA1EnabledVerifies(t *testing.T) {
	key, certPEM := redirectTestKey(t)
	raw := signedRedirectQuery(t, key, redirectAlgSHA1, "SAMLRequest", sampleSAMLRequest, redirectStr(exoticRelay))
	require.NoError(t, sha1EnabledUseCase().VerifyInboundRedirectSignature(redirectRequest(raw), certPEM),
		"SHA-1 redirect signature must verify when SHA-1 is explicitly enabled")
}

// ---- Embedded / POST binding (Path 2) --------------------------------------

// embeddedSigningKeyStore adapts an RSA key + DER cert to goxmldsig's signing
// keystore for building embedded-signature fixtures.
type embeddedSigningKeyStore struct {
	key     *rsa.PrivateKey
	certDER []byte
}

func (k embeddedSigningKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return k.key, k.certDER, nil
}

// embeddedSigningMaterial returns an RSA key, its DER certificate (for the signing
// keystore/KeyInfo) and the parsed certificate (for the verifying cert store).
func embeddedSigningMaterial(t *testing.T) (*rsa.PrivateKey, []byte, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "idp.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, der, cert
}

// signEmbedded produces an enveloped-signed element using the given hash for BOTH
// the signature and the digest (goxmldsig ties them to one Hash).
func signEmbedded(t *testing.T, key *rsa.PrivateKey, certDER []byte, hash crypto.Hash) *etree.Element {
	t.Helper()
	ctx := dsig.NewDefaultSigningContext(embeddedSigningKeyStore{key: key, certDER: certDER})
	ctx.Hash = hash
	el := etree.NewElement("Data")
	el.CreateAttr("ID", "_k-embedded")
	el.CreateElement("Value").SetText("payload")
	signed, err := ctx.SignEnveloped(el)
	require.NoError(t, err)
	return signed
}

func serializeElement(t *testing.T, el *etree.Element) []byte {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	b, err := doc.WriteToBytes()
	require.NoError(t, err)
	return b
}

// K4: a SHA-256 embedded signature verifies under the default (strict) policy.
func TestSAMLSigPolicy_K4_EmbeddedSHA256DefaultVerifies(t *testing.T) {
	key, certDER, cert := embeddedSigningMaterial(t)
	signed := serializeElement(t, signEmbedded(t, key, certDER, crypto.SHA256))
	require.NoError(t, verifyPostSignature(signed, cert, strictPolicyUseCase().signaturePolicy()),
		"SHA-256 embedded signature must verify under the default policy")
}

// K5 — TEETH. A SHA-1 embedded signature is rejected under the default policy,
// even though it is cryptographically valid.
func TestSAMLSigPolicy_K5_EmbeddedSHA1DefaultRejected(t *testing.T) {
	key, certDER, cert := embeddedSigningMaterial(t)
	signed := serializeElement(t, signEmbedded(t, key, certDER, crypto.SHA1))
	err := verifyPostSignature(signed, cert, strictPolicyUseCase().signaturePolicy())
	require.ErrorIs(t, err, errSHA1SignatureDisabled,
		"SHA-1 embedded signature must be rejected by policy under the default")
}

// buildSHA256SigOverSHA1Digest hand-builds a document whose SignatureMethod is
// RSA-SHA256 but whose Reference DigestMethod is SHA-1, and which is nonetheless
// cryptographically valid (real SHA-1 digest, real RSA-SHA256 signature over the
// canonicalized SignedInfo) so goxmldsig's default validator ACCEPTS it. goxmldsig
// cannot emit this directly (it uses one Hash for both), so we sign at SHA-1, then
// switch the SignatureMethod to RSA-SHA256 and re-sign the SignedInfo — leaving the
// SHA-1 digest intact. This is the case the digest-side policy must catch.
func buildSHA256SigOverSHA1Digest(t *testing.T, key *rsa.PrivateKey, certDER []byte) []byte {
	t.Helper()
	signed := signEmbedded(t, key, certDER, crypto.SHA1)
	sig := childByLocalName(signed, "Signature")
	require.NotNil(t, sig, "goxmldsig must produce a Signature child")
	signedInfo := childByLocalName(sig, "SignedInfo")
	require.NotNil(t, signedInfo)

	sm := childByLocalName(signedInfo, "SignatureMethod")
	require.NotNil(t, sm)
	require.Equal(t, dsig.RSASHA1SignatureMethod, sm.SelectAttrValue("Algorithm", ""))
	// Switch only the signature method to SHA-256; the Reference DigestMethod stays
	// SHA-1 with goxmldsig's own (valid) SHA-1 digest value.
	sm.CreateAttr("Algorithm", dsig.RSASHA256SignatureMethod)

	// Re-sign the SignedInfo over the EXACT bytes goxmldsig's validator recomputes:
	// build the ancestor namespace context (so xmlns:ds is in scope), detach the
	// SignedInfo with it, and serialize with etree's canonical settings — the same
	// getCanonicalSignedInfo path goxmldsig uses. SignatureValue lives outside
	// SignedInfo, so replacing it afterwards does not perturb this.
	nsCtx, err := etreeutils.NSBuildParentContext(sig)
	require.NoError(t, err)
	canonSignedInfo, err := etreeutils.NSFindOneChildCtx(nsCtx, sig, "http://www.w3.org/2000/09/xmldsig#", "SignedInfo")
	require.NoError(t, err)
	canonDoc := etree.NewDocument()
	canonDoc.SetRoot(canonSignedInfo.Copy())
	canonDoc.WriteSettings = etree.WriteSettings{CanonicalAttrVal: true, CanonicalEndTags: true, CanonicalText: true}
	canon, err := canonDoc.WriteToBytes()
	require.NoError(t, err)
	digest := sha256.Sum256(canon)
	newSig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	sv := childByLocalName(sig, "SignatureValue")
	require.NotNil(t, sv)
	sv.SetText(base64.StdEncoding.EncodeToString(newSig))

	return serializeElement(t, signed)
}

// K6 — TEETH. A SHA-256 signature over a SHA-1 DIGEST is rejected under the default
// policy. The digest is where collision resistance lives, so this is the case most
// likely to be missed.
func TestSAMLSigPolicy_K6_EmbeddedSHA256SigSHA1DigestRejected(t *testing.T) {
	key, certDER, cert := embeddedSigningMaterial(t)
	doc := buildSHA256SigOverSHA1Digest(t, key, certDER)
	err := verifyPostSignature(doc, cert, strictPolicyUseCase().signaturePolicy())
	require.ErrorIs(t, err, errSHA1DigestDisabled,
		"a SHA-256 signature over a SHA-1 digest must be rejected by the digest policy")
}
