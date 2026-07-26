package handlers_test

// Inbound ACS harness — a reusable tool for driving Shyntr's REAL Assertion
// Consumer Service HTTP endpoint with a SAML Response that Shyntr did NOT issue.
//
// WHY THIS EXISTS
// Shyntr's inbound federation path (the ACS handler → HandleACS → crewjam
// ParseResponse) had no test that fed it a Response built by an independent,
// external Identity Provider. Every prior SAML response test either drove the IdP
// side (Shyntr issuing) or exercised the use case in isolation. Three deferred
// items — SHA-1 inbound rejection, empty-mapping attribute loss on ACS, and
// InResponseTo enforcement — all need exactly this: an arbitrary, independently
// signed Response POSTed to the real ACS endpoint. This file builds that tool. It
// implements none of those three items; it only proves the tool drives the path.
//
// WHY THE RESPONSE IS BUILT OUTSIDE SHYNTR (deliberate, not circular)
// The Response is constructed and signed by TEST-OWNED code with a TEST-GENERATED
// key, representing a fictional external IdP that Shyntr federates FROM. It is
// NEVER produced by GenerateSAMLResponse or any Shyntr issuance code. If Shyntr
// signed the Response we would only be proving Shyntr accepts its own output —
// worthless for verifying inbound trust. Signing with goxmldsig directly here is
// therefore correct: goxmldsig is the external IdP's signer, not Shyntr's, so
// there is no circular verification. The fixture key's certificate is registered
// on the SAML CONNECTION (the inbound trust anchor), never on a client.
//
// Signature canonicalization is exclusive C14N (http://www.w3.org/2001/10/xml-exc-c14n#),
// the algorithm real IdPs (ADFS, Keycloak) use. It keeps a separately signed
// Assertion's digest stable when the Assertion is embedded under the Response,
// because exclusive C14N ignores in-scope-but-unused ancestor namespaces.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/security"
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

// signTarget selects which element(s) of the inbound Response the fixture IdP
// signs. A real external IdP signs the Assertion (WantAssertionsSigned), the
// Response, or both; the downstream work orders need to vary this.
type signTarget int

const (
	signAssertion signTarget = iota // sign the Assertion only (WantAssertionsSigned)
	signResponse                    // sign the Response only
	signBoth                        // sign both
)

// fixtureIdP is a fictional external Identity Provider: an entity ID plus a
// test-generated RSA key and self-signed certificate. All material is ephemeral
// and in-memory — nothing is written to a tracked path.
type fixtureIdP struct {
	entityID string
	key      *rsa.PrivateKey
	certDER  []byte
	certPEM  string
}

// newFixtureIdP generates a fresh external-IdP identity. example.test only.
func newFixtureIdP(t *testing.T, entityID string) *fixtureIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fixture-external-idp.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return &fixtureIdP{entityID: entityID, key: key, certDER: der, certPEM: certPEM}
}

// fixtureIdPKeyStore adapts the fixture key + certificate to goxmldsig's signing
// key store interface.
type fixtureIdPKeyStore struct {
	key *rsa.PrivateKey
	der []byte
}

func (k fixtureIdPKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) { return k.key, k.der, nil }

// inboundResponseParams fully describes the Response the fixture IdP will emit.
// Every field a downstream work order needs to vary is exposed: subject,
// attributes, key material (via the idp passed to buildInboundSAMLResponse),
// signature algorithm (hash), what is signed (target), audience, destination,
// recipient, InResponseTo, and the Conditions / SubjectConfirmation timestamps.
type inboundResponseParams struct {
	issuer       string
	subject      string
	nameIDFormat string
	attributes   map[string]string

	audience     string
	destination  string
	recipient    string
	inResponseTo string

	issueInstant time.Time
	notBefore    time.Time
	notOnOrAfter time.Time
	subjNotAfter time.Time

	target signTarget
	hash   crypto.Hash

	responseID  string
	assertionID string
}

// defaultInboundParams returns parameters that produce a Response the real ACS
// path accepts: issuer/audience/destination/recipient all matching this env's SP,
// timestamps around now (crewjam validates against wall-clock time, independent of
// any injected Shyntr clock), an Assertion-only SHA-256 signature, and no
// InResponseTo (IdP-initiated; the SP is configured AllowIDPInitiated).
func defaultInboundParams(env *oidcE2EEnv, idp *fixtureIdP) inboundResponseParams {
	now := time.Now().UTC()
	base := fmt.Sprintf("%s/t/%s/saml", env.cfg.BaseIssuerURL, env.cfg.DefaultTenantID)
	acs := base + "/sp/acs"
	return inboundResponseParams{
		issuer:       idp.entityID,
		subject:      "external-subject@example.test",
		nameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
		attributes:   map[string]string{},
		audience:     base,
		destination:  acs,
		recipient:    acs,
		inResponseTo: "",
		issueInstant: now,
		notBefore:    now.Add(-5 * time.Minute),
		notOnOrAfter: now.Add(5 * time.Minute),
		subjNotAfter: now.Add(5 * time.Minute),
		target:       signAssertion,
		hash:         crypto.SHA256,
		responseID:   "_resp-" + randHex(),
		assertionID:  "_assert-" + randHex(),
	}
}

// buildInboundSAMLResponse constructs and signs a SAML Response as the fixture IdP
// and returns it base64-encoded, ready to POST as the SAMLResponse form value.
func buildInboundSAMLResponse(t *testing.T, idp *fixtureIdP, p inboundResponseParams) string {
	t.Helper()

	assertionEl := readElement(t, buildAssertionXML(p))
	if p.target == signAssertion || p.target == signBoth {
		assertionEl = signEnvelopedExclusive(t, idp, assertionEl, p.hash)
	}

	responseEl := readElement(t, buildResponseShellXML(p))
	responseEl.AddChild(assertionEl)

	if p.target == signResponse || p.target == signBoth {
		responseEl = signEnvelopedExclusive(t, idp, responseEl, p.hash)
	}

	out := etree.NewDocument()
	out.SetRoot(responseEl)
	xmlBytes, err := out.WriteToBytes()
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(xmlBytes)
}

// buildResponseShellXML builds the Response element (Issuer + Status) without the
// Assertion, which is appended after any Assertion-level signing.
func buildResponseShellXML(p inboundResponseParams) string {
	return `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
		` ID="` + p.responseID + `" Version="2.0" IssueInstant="` + rfc3339(p.issueInstant) + `" Destination="` + p.destination + `">` +
		`<saml:Issuer>` + p.issuer + `</saml:Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
		`</samlp:Response>`
}

// buildAssertionXML builds a standalone Assertion element that self-declares its
// namespace so its exclusive-C14N digest is stable once embedded in the Response.
func buildAssertionXML(p inboundResponseParams) string {
	var attrs strings.Builder
	if len(p.attributes) > 0 {
		attrs.WriteString(`<saml:AttributeStatement>`)
		for name, value := range p.attributes {
			attrs.WriteString(`<saml:Attribute Name="` + name + `"><saml:AttributeValue>` + value + `</saml:AttributeValue></saml:Attribute>`)
		}
		attrs.WriteString(`</saml:AttributeStatement>`)
	}

	inResponseToAttr := ""
	if p.inResponseTo != "" {
		inResponseToAttr = ` InResponseTo="` + p.inResponseTo + `"`
	}

	return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
		` ID="` + p.assertionID + `" Version="2.0" IssueInstant="` + rfc3339(p.issueInstant) + `">` +
		`<saml:Issuer>` + p.issuer + `</saml:Issuer>` +
		`<saml:Subject>` +
		`<saml:NameID Format="` + p.nameIDFormat + `">` + p.subject + `</saml:NameID>` +
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<saml:SubjectConfirmationData Recipient="` + p.recipient + `" NotOnOrAfter="` + rfc3339(p.subjNotAfter) + `"` + inResponseToAttr + `/>` +
		`</saml:SubjectConfirmation>` +
		`</saml:Subject>` +
		`<saml:Conditions NotBefore="` + rfc3339(p.notBefore) + `" NotOnOrAfter="` + rfc3339(p.notOnOrAfter) + `">` +
		`<saml:AudienceRestriction><saml:Audience>` + p.audience + `</saml:Audience></saml:AudienceRestriction>` +
		`</saml:Conditions>` +
		`<saml:AuthnStatement AuthnInstant="` + rfc3339(p.issueInstant) + `">` +
		`<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>` +
		`</saml:AuthnStatement>` +
		attrs.String() +
		`</saml:Assertion>`
}

// signEnvelopedExclusive signs an element in place as the fixture IdP, using an
// enveloped signature with exclusive C14N and the requested hash (crypto.SHA256 or
// crypto.SHA1). goxmldsig's DefaultIdAttr is "ID", matching what crewjam's inbound
// validator resolves references against, so no override is needed.
func signEnvelopedExclusive(t *testing.T, idp *fixtureIdP, el *etree.Element, hash crypto.Hash) *etree.Element {
	t.Helper()
	ctx := dsig.NewDefaultSigningContext(fixtureIdPKeyStore{key: idp.key, der: idp.certDER})
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	ctx.Hash = hash
	signed, err := ctx.SignEnveloped(el)
	require.NoError(t, err)
	return signed
}

// acsOutcome is the full result the ACS handler produced for a driven Response.
type acsOutcome struct {
	status     int    // HTTP status code
	location   string // Location header (set on acceptance → resume/continue redirect)
	errorCode  string // X-Shyntr-Error-Code header (set on rejection → failure category)
	samlStatus string // top-level SAML StatusCode Value if the body carries one
	body       string // raw handler body
}

// driveInboundACS wires the inbound prerequisites Shyntr's ACS requires — a
// persisted login request, a CSRF-bound relay state, and the matching CSRF cookie
// — then POSTs the given base64 Response to the REAL ACS endpoint through the test
// router and returns the full outcome. The Response is built by the caller so it
// retains complete control over signing and content.
func driveInboundACS(t *testing.T, env *oidcE2EEnv, connectionID, samlResponseB64 string) acsOutcome {
	t.Helper()
	tenantID := env.cfg.DefaultTenantID
	challenge := "lc-" + randHex()
	csrf := "csrf-" + randHex()

	// A login request must exist for the challenge the relay state carries.
	// Protocol "saml" makes a successful ACS resume to the SAML resume endpoint,
	// so acceptance surfaces as a 302 to /saml/resume.
	require.NoError(t, env.db.Create(&models.LoginRequestGORM{
		ID:       challenge,
		TenantID: tenantID,
		ClientID: "inbound-fixture-sp",
		Protocol: "saml",
		Active:   true,
	}).Error)

	relayState, err := env.state.Issue(context.Background(), security.IssueFederationStateInput{
		Action:         security.FederationActionSAMLLogin,
		TenantID:       tenantID,
		LoginChallenge: challenge,
		ConnectionID:   connectionID,
		CSRFToken:      csrf,
		TTL:            10 * time.Minute,
	})
	require.NoError(t, err)

	form := url.Values{}
	form.Set("SAMLResponse", samlResponseB64)
	form.Set("RelayState", relayState)

	resp := serveRequest(t, env.router, http.MethodPost,
		fmt.Sprintf("/t/%s/saml/sp/acs", tenantID),
		strings.NewReader(form.Encode()),
		map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Cookie":       "shyntr_fed_csrf=" + csrf,
		})

	return acsOutcome{
		status:     resp.Code,
		location:   resp.Header().Get("Location"),
		errorCode:  resp.Header().Get("X-Shyntr-Error-Code"),
		samlStatus: extractSAMLStatusCode(resp.Body.String()),
		body:       resp.Body.String(),
	}
}

// registerFixtureIdPConnection registers the fixture IdP as a trusted SAML
// connection, reusing the E2E fixture that stores the connection's trust
// certificate in IdpCertificate — the same field HandleACS reads to build the SP's
// IDPMetadata signing trust.
func registerFixtureIdPConnection(t *testing.T, env *oidcE2EEnv, connectionID string, idp *fixtureIdP) {
	t.Helper()
	createSAMLConnectionFixture(t, env.db, env.cfg.DefaultTenantID, connectionID,
		idp.entityID, "https://idp.example.test/sso", idp.certPEM)
}

// --- small helpers ---------------------------------------------------------

func readElement(t *testing.T, xmlStr string) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(xmlStr))
	root := doc.Root()
	require.NotNil(t, root)
	return root
}

func rfc3339(ts time.Time) string { return ts.UTC().Format(time.RFC3339) }

func randHex() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// extractSAMLStatusCode returns the first SAML StatusCode Value in a body, or ""
// if the body is not XML or carries no StatusCode.
func extractSAMLStatusCode(body string) string {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(body); err != nil || doc.Root() == nil {
		return ""
	}
	for _, el := range doc.FindElements("//StatusCode") {
		if v := el.SelectAttrValue("Value", ""); v != "" {
			return v
		}
	}
	return ""
}

// TestSAMLInboundACS_ValidSHA256ResponseIsAccepted is the single proving test: it
// demonstrates the harness drives the real ACS path by asserting one already-true
// property — a valid SHA-256-signed Assertion from a fixture IdP trusted on the
// connection is ACCEPTED. It intentionally makes no claim about SHA-1, empty
// mappings, or InResponseTo; those belong to separate work orders.
func TestSAMLInboundACS_ValidSHA256ResponseIsAccepted(t *testing.T) {
	env := setupOIDCE2EEnv(t)

	idp := newFixtureIdP(t, "https://idp.example.test/inbound-accept")
	const connectionID = "conn-inbound-accept"
	registerFixtureIdPConnection(t, env, connectionID, idp)

	params := defaultInboundParams(env, idp)
	params.subject = "external-user@example.test"
	params.attributes = map[string]string{"email": "external-user@example.test"}

	responseB64 := buildInboundSAMLResponse(t, idp, params)
	outcome := driveInboundACS(t, env, connectionID, responseB64)

	require.Equalf(t, http.StatusFound, outcome.status,
		"a valid SHA-256-signed Response from a trusted fixture IdP must be accepted by ACS (error_code=%q)", outcome.errorCode)
	require.Contains(t, outcome.location, fmt.Sprintf("/t/%s/saml/resume", env.cfg.DefaultTenantID),
		"acceptance must resume the originating login flow")
	require.Empty(t, outcome.errorCode, "an accepted Response must not set a failure category")
}
