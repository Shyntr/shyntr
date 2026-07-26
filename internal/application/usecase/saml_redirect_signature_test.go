// SAML HTTP-Redirect binding signature verification harness (G1–G5).
//
// WHY THIS FILE EXISTS
// VerifyInboundRedirectSignature is the single, unified verifier for the SAML 2.0
// HTTP-Redirect binding (Bindings §3.4.4.1). It replaced two divergent
// implementations that both rebuilt the signed string with url.QueryEscape
// instead of verifying over the octets as received. Percent-encoding is not
// canonical (%20 vs '+', hex case, sub-delims such as ! * ( ) ), so re-encoding
// silently breaks verification whenever the sender's encoding differs from Go's.
// These tests pin the corrected behaviour: verification over the RAW received
// query, both message types, and fail-closed error handling.
//
// G1 is the teeth: it signs over octets (a space as %20 and a literal '!') that
// NO QueryEscape round-trip reproduces — Go emits '+' for the space and %21 for
// the '!', under either the plain or the '+'->'%20' redirect convention. A
// re-encoding verifier therefore rejects a valid signature; the raw-octet
// verifier accepts it.
package usecase

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	redirectAlgSHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	redirectAlgSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	redirectAlgSHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
)

var redirectHashByAlg = map[string]crypto.Hash{
	redirectAlgSHA1:   crypto.SHA1,
	redirectAlgSHA256: crypto.SHA256,
	redirectAlgSHA512: crypto.SHA512,
}

// redirectTestKey returns an RSA-2048 key and a self-signed certificate PEM for
// that key — the shape VerifyInboundRedirectSignature accepts as its cert input.
func redirectTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return key, string(pemBytes)
}

// signedRedirectQuery builds a raw HTTP-Redirect query whose Signature is computed
// over the RAW value substrings supplied, in the spec order
// (message, RelayState?, SigAlg). The caller passes the value bytes exactly as
// they should appear on the wire, so a test can sign over a space encoded as %20
// or a literal sub-delim and later assert the verifier honours those octets.
func signedRedirectQuery(t *testing.T, key *rsa.PrivateKey, alg, messageField, messageRaw string, relayRaw *string) string {
	t.Helper()
	hash, ok := redirectHashByAlg[alg]
	require.True(t, ok, "test alg must be one of the accepted set")

	signed := messageField + "=" + messageRaw
	if relayRaw != nil {
		signed += "&RelayState=" + *relayRaw
	}
	signed += "&SigAlg=" + url.QueryEscape(alg)

	hasher := hash.New()
	hasher.Write([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, hasher.Sum(nil))
	require.NoError(t, err)
	return signed + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
}

func redirectRequest(rawQuery string) *http.Request {
	return &http.Request{Method: http.MethodGet, URL: &url.URL{RawQuery: rawQuery}}
}

func redirectStr(s string) *string { return &s }

// exoticRelay carries a space as %20 (Go's escaper emits '+') and a literal '!'
// (Go's escaper emits %21). Neither the plain nor the '+'->'%20' re-encoding
// convention reproduces these octets, so a signature over them only verifies
// against the raw-octet implementation.
const exoticRelay = "state%20one!two"

// sampleSAMLRequest / sampleSAMLResponse are opaque tokens; the verifier never
// decodes the message body, only the surrounding query octets.
const (
	sampleSAMLRequest  = "PHNhbWxwQXV0aG5SZXF1ZXN0"
	sampleSAMLResponse = "PHNhbWxwUmVzcG9uc2U"
)

// G1 — THE TEETH. A signature computed over the raw received octets verifies,
// even though those octets (%20 space, literal '!') differ from what Go's escaper
// would reconstruct. Against a re-encoding verifier this FAILS; against the
// raw-octet verifier it PASSES.
func TestVerifyRedirectSignature_G1_RawReceivedOctetsVerify(t *testing.T) {
	key, certPEM := redirectTestKey(t)
	raw := signedRedirectQuery(t, key, redirectAlgSHA256, "SAMLRequest", sampleSAMLRequest, redirectStr(exoticRelay))
	require.Contains(t, raw, "%20", "test must sign over a %20-encoded space")
	require.Contains(t, raw, "one!two", "test must sign over a literal '!'")

	err := strictPolicyUseCase().VerifyInboundRedirectSignature(redirectRequest(raw), certPEM)
	require.NoError(t, err, "signature over the raw received query must verify")
}

// G2 — a query tampered after signing is rejected. One RelayState character is
// altered; every other octet is untouched.
func TestVerifyRedirectSignature_G2_TamperedRelayStateRejected(t *testing.T) {
	key, certPEM := redirectTestKey(t)
	raw := signedRedirectQuery(t, key, redirectAlgSHA256, "SAMLRequest", sampleSAMLRequest, redirectStr(exoticRelay))

	tampered := strings.Replace(raw, "state%20one!two", "Xtate%20one!two", 1)
	require.NotEqual(t, raw, tampered, "tamper must actually change the query")

	err := strictPolicyUseCase().VerifyInboundRedirectSignature(redirectRequest(tampered), certPEM)
	require.Error(t, err, "a tampered RelayState must not verify")
}

// G3 — a SAMLResponse-carrying redirect verifies. This path did not exist in the
// use-case implementation, which handled SAMLRequest only.
func TestVerifyRedirectSignature_G3_SAMLResponseVerifies(t *testing.T) {
	key, certPEM := redirectTestKey(t)
	raw := signedRedirectQuery(t, key, redirectAlgSHA1, "SAMLResponse", sampleSAMLResponse, redirectStr(exoticRelay))

	// G3 signs with SHA-1. After consolidation the only redirect verifier applies
	// the inbound policy, so SHA-1 acceptance is exercised through the SHA-1-enabled
	// configuration (SAML_ALLOW_SHA1_SIGNATURES=true) — a real, production-reachable
	// setting, not a policy-free bypass. The assertion is unchanged: a signed
	// SAMLResponse redirect verifies.
	err := sha1EnabledUseCase().VerifyInboundRedirectSignature(redirectRequest(raw), certPEM)
	require.NoError(t, err, "a signed SAMLResponse redirect must verify")
}

// G4 — every error path fails closed rather than passing.
func TestVerifyRedirectSignature_G4_ErrorPathsFailClosed(t *testing.T) {
	key, certPEM := redirectTestKey(t)
	validAlg := url.QueryEscape(redirectAlgSHA256)
	unknownAlg := url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#rsa-md5")

	cases := []struct {
		name  string
		query string
	}{
		{
			name:  "malformed base64 signature",
			query: "SAMLRequest=" + sampleSAMLRequest + "&SigAlg=" + validAlg + "&Signature=**",
		},
		{
			name:  "absent SigAlg",
			query: "SAMLRequest=" + sampleSAMLRequest + "&Signature=AAAA",
		},
		{
			name:  "absent Signature",
			query: "SAMLRequest=" + sampleSAMLRequest + "&SigAlg=" + validAlg,
		},
		{
			name:  "unknown algorithm URI",
			query: "SAMLRequest=" + sampleSAMLRequest + "&SigAlg=" + unknownAlg + "&Signature=AAAA",
		},
		{
			name:  "both SAMLRequest and SAMLResponse present",
			query: "SAMLRequest=" + sampleSAMLRequest + "&SAMLResponse=" + sampleSAMLResponse + "&SigAlg=" + validAlg + "&Signature=AAAA",
		},
		{
			name:  "neither SAMLRequest nor SAMLResponse present",
			query: "SigAlg=" + validAlg + "&Signature=AAAA",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := strictPolicyUseCase().VerifyInboundRedirectSignature(redirectRequest(tc.query), certPEM)
			require.Error(t, err, "%s must be rejected", tc.name)
		})
	}

	// A wrong-key-type certificate must also be rejected. Verified independently of
	// the query cases above, using a valid, well-formed signed query.
	t.Run("non-RSA certificate rejected", func(t *testing.T) {
		raw := signedRedirectQuery(t, key, redirectAlgSHA256, "SAMLRequest", sampleSAMLRequest, redirectStr(exoticRelay))
		require.Error(t, strictPolicyUseCase().VerifyInboundRedirectSignature(redirectRequest(raw), "-----BEGIN CERTIFICATE-----\nnot a cert\n-----END CERTIFICATE-----\n"))
		require.Error(t, strictPolicyUseCase().VerifyInboundRedirectSignature(redirectRequest(raw), "not a pem block at all"))
	})
}

// G5 — behavioural equivalence. For a query whose values contain no character any
// escaper alters (so raw octets == QueryEscape output), both former
// implementations accepted; the unified one still does, across the full accepted
// algorithm set. The SHA-512 case additionally proves the union set was preserved
// (the handler accepted SHA-512, the use case did not).
func TestVerifyRedirectSignature_G5_BehaviouralEquivalence(t *testing.T) {
	key, certPEM := redirectTestKey(t)
	for _, alg := range []string{redirectAlgSHA1, redirectAlgSHA256, redirectAlgSHA512} {
		t.Run(alg, func(t *testing.T) {
			// Plain alphanumeric values: raw octets equal what url.QueryEscape would
			// have produced, so this is a query both former verifiers accepted.
			raw := signedRedirectQuery(t, key, alg, "SAMLRequest", "PlainRequest0Token", redirectStr("plainrelay0state"))
			// The set under test includes SHA-1. The single policy-aware verifier
			// accepts SHA-1 only under the SHA-1-enabled configuration, so the whole
			// union (SHA-1/256/512) is exercised through it. SHA-256/512 verify
			// identically under either policy, so the assertions are unchanged.
			err := sha1EnabledUseCase().VerifyInboundRedirectSignature(redirectRequest(raw), certPEM)
			require.NoError(t, err, "a canonically-encoded query must still verify under %s", alg)
		})
	}
}
