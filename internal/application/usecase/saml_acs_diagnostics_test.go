// Inbound ACS diagnostics (L1–L3).
//
// crewjam collapses every ParseResponse failure to the opaque "Authentication
// failed". These tests prove Shyntr now surfaces a distinguishable, document-free
// category per failure class, and — the mandatory negative control (L2) — that no
// marker value from the response ever appears in what the code emits, even for a
// failure class whose raw PrivateErr provably carries a document-derived value.
//
// The fixtures drive the real crewjam ParseXMLResponse path (the same code
// HandleACS reaches through ParseResponse), so classifyACSValidationError is
// exercised against genuine *InvalidResponseError values.
package usecase

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjamsaml "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

const (
	acsIdpEntity  = "https://idp.example.test/metadata"
	acsAcsURL     = "https://sp.example.test/t/tenant-a/saml/sp/acs"
	acsSpEntity   = "https://sp.example.test/t/tenant-a/saml"
	acsMarkerName = "MARKER-NAMEID-abc123"
	acsMarkerAttr = "MARKER-ATTR-xyz789"
	acsMarkerDest = "MARKER-DEST-inject-987"
)

type acsSignKS struct {
	key *rsa.PrivateKey
	der []byte
}

func (k acsSignKS) GetKeyPair() (*rsa.PrivateKey, []byte, error) { return k.key, k.der, nil }

func acsMaterial(t *testing.T) (*rsa.PrivateKey, []byte, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "acs idp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, der, cert
}

func acsSP(idpCert *x509.Certificate, sha1Verifier bool) *crewjamsaml.ServiceProvider {
	acs, _ := url.Parse(acsAcsURL)
	meta, _ := url.Parse("https://sp.example.test/t/tenant-a/saml/sp/metadata")
	idp := &crewjamsaml.EntityDescriptor{EntityID: acsIdpEntity}
	idp.IDPSSODescriptors = []crewjamsaml.IDPSSODescriptor{{}}
	idp.IDPSSODescriptors[0].KeyDescriptors = append(idp.IDPSSODescriptors[0].KeyDescriptors, crewjamsaml.KeyDescriptor{
		Use:     "signing",
		KeyInfo: crewjamsaml.KeyInfo{X509Data: crewjamsaml.X509Data{X509Certificates: []crewjamsaml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(idpCert.Raw)}}}},
	})
	sp := &crewjamsaml.ServiceProvider{EntityID: acsSpEntity, AcsURL: *acs, MetadataURL: *meta,
		IDPMetadata: idp, AllowIDPInitiated: true}
	if sha1Verifier {
		sp.SignatureVerifier = signatureAlgorithmVerifier{policy: signatureAlgorithmPolicy{allowSHA1: false}}
	}
	return sp
}

func acsAssertion(issuer, audience, condNotAfter, subjNotAfter, issueInstant string) string {
	return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_acsassert" Version="2.0" IssueInstant="` + issueInstant + `">` +
		`<saml:Issuer>` + issuer + `</saml:Issuer>` +
		`<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">` + acsMarkerName + `</saml:NameID>` +
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="` + acsAcsURL + `" NotOnOrAfter="` + subjNotAfter + `"/></saml:SubjectConfirmation>` +
		`</saml:Subject>` +
		`<saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="` + condNotAfter + `"><saml:AudienceRestriction><saml:Audience>` + audience + `</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
		`<saml:AuthnStatement AuthnInstant="` + issueInstant + `"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
		`<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>` + acsMarkerAttr + `</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>` +
		`</saml:Assertion>`
}

func acsSignedResponse(t *testing.T, key *rsa.PrivateKey, der []byte, assertionXML, destination, issueInstant string, hash crypto.Hash, tamper bool) []byte {
	t.Helper()
	respXML := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_acsresp" Version="2.0" IssueInstant="` + issueInstant + `" Destination="` + destination + `">` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
		assertionXML +
		`</samlp:Response>`
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(respXML))
	ctx := dsig.NewDefaultSigningContext(acsSignKS{key: key, der: der})
	ctx.Hash = hash
	signed, err := ctx.SignEnveloped(doc.Root())
	require.NoError(t, err)
	if tamper {
		sv := signed.FindElement(".//SignatureValue")
		require.NotNil(t, sv)
		sv.SetText("A" + sv.Text()[1:])
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	b, err := out.WriteToBytes()
	require.NoError(t, err)
	return b
}

type acsCase struct {
	issuer, audience, condNotAfter, destination string
	hash                                        crypto.Hash
	tamper, sha1Verifier                        bool
}

// acsRealError drives the real crewjam ParseXMLResponse and returns the
// *InvalidResponseError it produces, exactly as HandleACS receives it.
func acsRealError(t *testing.T, c acsCase) error {
	t.Helper()
	now := time.Now().UTC()
	fresh := now.Format(time.RFC3339)
	future := now.Add(time.Hour).Format(time.RFC3339)
	key, der, cert := acsMaterial(t)
	respXML := acsSignedResponse(t, key, der, acsAssertion(c.issuer, c.audience, c.condNotAfter, future, fresh), c.destination, fresh, c.hash, c.tamper)
	sp := acsSP(cert, c.sha1Verifier)
	acs, _ := url.Parse(acsAcsURL)
	_, err := sp.ParseXMLResponse(respXML, []string{}, *acs)
	require.Error(t, err)
	return err
}

func validCase() acsCase {
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	return acsCase{issuer: acsIdpEntity, audience: acsSpEntity, condNotAfter: future, destination: acsAcsURL, hash: crypto.SHA256}
}

// surfacedDiagnostic mirrors exactly what HandleACS emits for a ParseResponse
// failure — the only ParseResponse-derived text that leaves the use case.
func surfacedDiagnostic(err error) string {
	return fmt.Sprintf("saml acs validation failed [%s]", classifyACSValidationError(err))
}

// L1: three distinct failure classes produce three distinct surfaced diagnostics.
func TestSAMLACSDiag_L1_ClassesAreDistinguishable(t *testing.T) {
	past := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)

	expired := validCase()
	expired.condNotAfter = past
	audience := validCase()
	audience.audience = "urn:wrong-audience"
	destination := validCase()
	destination.destination = "https://attacker.example/acs"

	dExpired := surfacedDiagnostic(acsRealError(t, expired))
	dAudience := surfacedDiagnostic(acsRealError(t, audience))
	dDestination := surfacedDiagnostic(acsRealError(t, destination))

	require.Contains(t, dExpired, acsFailExpired)
	require.Contains(t, dAudience, acsFailAudienceMismatch)
	require.Contains(t, dDestination, acsFailDestinationMismatch)

	// The three must be mutually distinct — this is what fails against the opaque
	// pre-change behaviour where every class produced the same string.
	require.NotEqual(t, dExpired, dAudience)
	require.NotEqual(t, dExpired, dDestination)
	require.NotEqual(t, dAudience, dDestination)
}

// L2 — MANDATORY NEGATIVE CONTROL. A failure whose raw PrivateErr provably carries
// a document-derived value (the destination-mismatch case quotes the inbound
// Destination) must still emit NONE of the marker values — not the injected
// destination, not the NameID, not the attribute value.
func TestSAMLACSDiag_L2_NoMarkerEscapes(t *testing.T) {
	c := validCase()
	c.destination = "https://attacker.example/" + acsMarkerDest
	realErr := acsRealError(t, c)

	// Precondition: the raw PrivateErr genuinely leaks the injected destination
	// marker, so this test is exercising real sanitization rather than a no-op.
	require.Contains(t, privateCauseMessage(realErr), acsMarkerDest,
		"fixture precondition: raw PrivateErr must carry the injected marker")

	surfaced := surfacedDiagnostic(realErr)
	category := classifyACSValidationError(realErr)

	for _, emitted := range []string{surfaced, category} {
		for _, marker := range []string{acsMarkerDest, acsMarkerName, acsMarkerAttr} {
			require.NotContainsf(t, emitted, marker,
				"emitted diagnostic %q must not contain marker %q", emitted, marker)
		}
	}
	require.Equal(t, acsFailDestinationMismatch, category)
}

// L3: the SHA-1 rejection is distinguishable from a signature-verification failure.
func TestSAMLACSDiag_L3_SHA1DistinctFromBadSignature(t *testing.T) {
	sha1 := validCase()
	sha1.hash = crypto.SHA1
	sha1.sha1Verifier = true

	badSig := validCase()
	badSig.tamper = true

	dSHA1 := surfacedDiagnostic(acsRealError(t, sha1))
	dBadSig := surfacedDiagnostic(acsRealError(t, badSig))

	require.Contains(t, dSHA1, acsFailSignatureAlgRejected)
	require.Contains(t, dBadSig, acsFailSignatureInvalid)
	require.NotEqual(t, dSHA1, dBadSig, "SHA-1 rejection must be distinguishable from a bad signature")
}
