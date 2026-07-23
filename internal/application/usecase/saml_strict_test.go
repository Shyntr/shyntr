// SAML strictness harness.
//
// WHY THIS FILE EXISTS
// Microsoft ADFS rejects Shyntr-issued SAML Responses with the XML reader error
// "'Element' is an invalid XmlNodeType." That error is raised before any
// signature evaluation: it is a structural (content-model) rejection. The root
// cause is that signElementXML (internal/application/usecase/saml_builder_usecase.go)
// delegates to goxmldsig SignEnveloped, which appends ds:Signature as the LAST
// child of the signed element. SAML 2.0 requires ds:Signature to appear
// immediately after Issuer. No reachable ADFS instance exists for testing, so
// this harness reproduces the relevant strictness in-repo and becomes the
// acceptance gate for every subsequent SAML signing change. It exercises the
// production signElementXML directly against real RSA-2048 key material and a
// real goxmldsig validation context — nothing is stubbed, faked, or bypassed.
//
// It proves three properties: (1) structural correctness (SAML 2.0 element
// ordering), (2) cryptographic integrity that survives nested signing and
// post-signing extraction, and (3) detection of tampering.
//
// WHY XSD WAS REJECTED
// Full XSD validation in Go requires cgo + libxml2, which would be forced into
// all three CI lanes and add an external system dependency. The defect class
// here is element ORDERING, which the hand-written, table-driven content-model
// checks below cover with zero new module dependencies (etree and goxmldsig are
// already in the graph). XSD is therefore unnecessary for this defect class.
//
// OUT OF SCOPE
// Datatype validation, cardinality constraints, and attribute constraints are
// explicitly out of scope. This harness only asserts child-sequence ordering,
// signature placement, KeyInfo/KeyName content, canonicalization/algorithm
// identifiers, and real cryptographic verification. It does not modify any
// production source file.

package usecase

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjamsaml "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SAML 2.0 namespaces used by the content-model tables and fixtures.
const (
	nsSAML  = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsSAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsDS    = "http://www.w3.org/2000/09/xmldsig#"

	exclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
)

// ---------------------------------------------------------------------------
// Process-wide signing material (RSA-2048 + self-signed cert), generated once.
// Key generation dominates package runtime, so it must not run per test.
// ---------------------------------------------------------------------------

var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
	testCert    *x509.Certificate
	testKeyErr  error
)

func testSigningMaterial(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	testKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			testKeyErr = fmt.Errorf("generate rsa key: %w", err)
			return
		}
		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Shyntr SAML Strictness Test IdP"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			testKeyErr = fmt.Errorf("create certificate: %w", err)
			return
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			testKeyErr = fmt.Errorf("parse certificate: %w", err)
			return
		}
		testKey, testCert = key, cert
	})
	require.NoError(t, testKeyErr)
	require.NotNil(t, testKey)
	require.NotNil(t, testCert)
	return testKey, testCert
}

// ---------------------------------------------------------------------------
// Fixtures. Each independently-signable element declares its own namespaces so
// a nested Assertion remains canonicalizable after extraction from its Response.
// Only example.test / example.invalid hostnames and synthetic identifiers.
// ---------------------------------------------------------------------------

// productionAttributeValueXML returns the exact serialized shape production
// emits for an AttributeValue carrying xsi:type="xs:string". It is DERIVED from
// the production marshalling path (encoding/xml over crewjamsaml.AttributeValue,
// mirroring saml_builder_usecase.go:695), never hand-written: Go's marshaller
// declares only the XMLSchema-instance namespace (as the auto-generated prefix
// "_XMLSchema-instance", which names the type attribute) and does NOT declare
// xmlns:xs, so the "xs:" in the value is a dangling QName. Deriving it at runtime
// keeps the fixture faithful even if the marshaller's prefix scheme changes.
func productionAttributeValueXML() string {
	b, err := xml.Marshal(crewjamsaml.AttributeValue{Type: "xs:string", Value: "subject@example.test"})
	if err != nil {
		// Static, deterministic input — marshalling cannot fail in practice.
		panic("marshal production AttributeValue: " + err.Error())
	}
	return string(b)
}

func assertionFixtureXML(id string) string {
	return fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">`+
		`<saml:Issuer>https://idp.example.test/metadata</saml:Issuer>`+
		`<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">subject@example.test</saml:NameID></saml:Subject>`+
		`<saml:Conditions NotBefore="2026-01-01T00:00:00Z" NotOnOrAfter="2026-01-01T01:00:00Z">`+
		`<saml:AudienceRestriction><saml:Audience>https://sp.example.test/metadata</saml:Audience></saml:AudienceRestriction>`+
		`</saml:Conditions>`+
		`<saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z">`+
		`<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>`+
		`</saml:AuthnStatement>`+
		`<saml:AttributeStatement><saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">`+
		`%s`+
		`</saml:Attribute></saml:AttributeStatement>`+
		`</saml:Assertion>`, id, productionAttributeValueXML())
}

func responseShellXML(id string) string {
	return fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://sp.example.test/acs">`+
		`<saml:Issuer>https://idp.example.test/metadata</saml:Issuer>`+
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`+
		`</samlp:Response>`, id)
}

func logoutResponseFixtureXML(id string) string {
	return fmt.Sprintf(`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://sp.example.test/slo" InResponseTo="_request-1">`+
		`<saml:Issuer>https://idp.example.test/metadata</saml:Issuer>`+
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`+
		`</samlp:LogoutResponse>`, id)
}

// newResponseWithAssertion builds a samlp:Response containing the given
// serialized assertion (signed or unsigned) as its trailing child.
func newResponseWithAssertion(t *testing.T, responseID string, assertion []byte) []byte {
	t.Helper()
	respDoc := etree.NewDocument()
	require.NoError(t, respDoc.ReadFromString(responseShellXML(responseID)))
	assertionDoc := etree.NewDocument()
	require.NoError(t, assertionDoc.ReadFromBytes(assertion))
	respDoc.Root().AddChild(assertionDoc.Root().Copy())
	out, err := respDoc.WriteToBytes()
	require.NoError(t, err)
	return out
}

// ---------------------------------------------------------------------------
// Content-model tables. Members of an xsd:choice group share a rank and may
// appear in any order among themselves; sequence members have ascending ranks.
// ---------------------------------------------------------------------------

type modelEntry struct {
	ns    string
	local string
	rank  int
}

var assertionModel = []modelEntry{
	{nsSAML, "Issuer", 0},
	{nsDS, "Signature", 1},
	{nsSAML, "Subject", 2},
	{nsSAML, "Conditions", 3},
	{nsSAML, "Advice", 4},
	// xsd:choice of statements — shared rank 5.
	{nsSAML, "Statement", 5},
	{nsSAML, "AuthnStatement", 5},
	{nsSAML, "AuthzDecisionStatement", 5},
	{nsSAML, "AttributeStatement", 5},
}

var responseModel = []modelEntry{
	{nsSAML, "Issuer", 0},
	{nsDS, "Signature", 1},
	{nsSAMLP, "Extensions", 2},
	{nsSAMLP, "Status", 3},
	// xsd:choice — shared rank 4.
	{nsSAML, "Assertion", 4},
	{nsSAML, "EncryptedAssertion", 4},
}

var logoutResponseModel = []modelEntry{
	{nsSAML, "Issuer", 0},
	{nsDS, "Signature", 1},
	{nsSAMLP, "Extensions", 2},
	{nsSAMLP, "Status", 3},
}

func contentModelFor(ns, local string) ([]modelEntry, bool) {
	switch ns + "|" + local {
	case nsSAMLP + "|Response":
		return responseModel, true
	case nsSAMLP + "|LogoutResponse":
		return logoutResponseModel, true
	case nsSAML + "|Assertion":
		return assertionModel, true
	}
	return nil, false
}

func rankOf(model []modelEntry, ns, local string) (int, bool) {
	for _, m := range model {
		if m.ns == ns && m.local == local {
			return m.rank, true
		}
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// Inspection helpers.
// ---------------------------------------------------------------------------

func qname(e *etree.Element) string {
	if e.Space != "" {
		return e.Space + ":" + e.Tag
	}
	return e.Tag
}

func observedOrder(e *etree.Element) []string {
	out := make([]string, 0, len(e.ChildElements()))
	for _, c := range e.ChildElements() {
		out = append(out, qname(c))
	}
	return out
}

func directChild(e *etree.Element, ns, local string) *etree.Element {
	for _, c := range e.ChildElements() {
		if c.Tag == local && c.NamespaceURI() == ns {
			return c
		}
	}
	return nil
}

func descend(root *etree.Element, path ...[2]string) *etree.Element {
	cur := root
	for _, step := range path {
		if cur == nil {
			return nil
		}
		cur = directChild(cur, step[0], step[1])
	}
	return cur
}

// collectOrderViolations validates child ordering against the content-model
// tables for every element that has a model, recursing into nested elements.
// Each message includes the observed child order.
func collectOrderViolations(root *etree.Element) []string {
	var msgs []string
	var walk func(e *etree.Element)
	walk = func(e *etree.Element) {
		if model, ok := contentModelFor(e.NamespaceURI(), e.Tag); ok {
			observed := observedOrder(e)
			lastRank := -1
			for _, c := range e.ChildElements() {
				rank, known := rankOf(model, c.NamespaceURI(), c.Tag)
				if !known {
					msgs = append(msgs, fmt.Sprintf("%s: unexpected child %s (observed order: %v)",
						qname(e), qname(c), observed))
					continue
				}
				if rank < lastRank {
					msgs = append(msgs, fmt.Sprintf("%s: child %s (rank %d) appears after a rank-%d child — sequence violation (observed order: %v)",
						qname(e), qname(c), rank, lastRank, observed))
				}
				if rank > lastRank {
					lastRank = rank
				}
			}
		}
		for _, c := range e.ChildElements() {
			walk(c)
		}
	}
	walk(root)
	return msgs
}

// signatureImmediatelyAfterIssuer asserts exactly one direct ds:Signature child,
// positioned immediately after Issuer. Returns the observed order and count for
// failure reporting.
func signatureImmediatelyAfterIssuer(root *etree.Element) (ok bool, observed []string, sigCount int) {
	children := root.ChildElements()
	observed = observedOrder(root)
	issuerIdx := -1
	for i, c := range children {
		if c.Tag == "Issuer" && c.NamespaceURI() == nsSAML {
			issuerIdx = i
			break
		}
	}
	for _, c := range children {
		if c.Tag == "Signature" && c.NamespaceURI() == nsDS {
			sigCount++
		}
	}
	if issuerIdx == -1 || sigCount != 1 || issuerIdx+1 >= len(children) {
		return false, observed, sigCount
	}
	next := children[issuerIdx+1]
	return next.Tag == "Signature" && next.NamespaceURI() == nsDS, observed, sigCount
}

// keyName returns the ds:KeyName text inside the root's direct ds:Signature
// KeyInfo, whether it exists, and the observed KeyInfo child order.
func keyName(root *etree.Element) (value string, present bool, keyInfoOrder []string) {
	keyInfo := descend(root, [2]string{nsDS, "Signature"}, [2]string{nsDS, "KeyInfo"})
	if keyInfo == nil {
		return "", false, nil
	}
	keyInfoOrder = observedOrder(keyInfo)
	kn := directChild(keyInfo, nsDS, "KeyName")
	if kn == nil {
		return "", false, keyInfoOrder
	}
	return kn.Text(), true, keyInfoOrder
}

func canonicalizationAlgorithm(root *etree.Element) string {
	el := descend(root,
		[2]string{nsDS, "Signature"},
		[2]string{nsDS, "SignedInfo"},
		[2]string{nsDS, "CanonicalizationMethod"})
	if el == nil {
		return ""
	}
	return el.SelectAttrValue("Algorithm", "")
}

func signatureMethodAlgorithm(root *etree.Element) string {
	el := descend(root,
		[2]string{nsDS, "Signature"},
		[2]string{nsDS, "SignedInfo"},
		[2]string{nsDS, "SignatureMethod"})
	if el == nil {
		return ""
	}
	return el.SelectAttrValue("Algorithm", "")
}

func digestMethodAlgorithm(root *etree.Element) string {
	el := descend(root,
		[2]string{nsDS, "Signature"},
		[2]string{nsDS, "SignedInfo"},
		[2]string{nsDS, "Reference"},
		[2]string{nsDS, "DigestMethod"})
	if el == nil {
		return ""
	}
	return el.SelectAttrValue("Algorithm", "")
}

// verifyEnveloped performs real cryptographic verification of an enveloped
// signature using goxmldsig, with the signing certificate as the only trust
// root. Returns nil only when the signature is cryptographically valid.
func verifyEnveloped(el *etree.Element, cert *x509.Certificate) error {
	store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	ctx := dsig.NewDefaultValidationContext(store)
	ctx.IdAttribute = "ID"
	_, err := ctx.Validate(el)
	return err
}

func parseSigned(t *testing.T, signed []byte) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(signed))
	root := doc.Root()
	require.NotNil(t, root)
	return root
}

// ---------------------------------------------------------------------------
// T-A: all three signing paths — placement, schema order, KeyName, and real
// cryptographic verification.
// ---------------------------------------------------------------------------

func TestSAMLStrict_A_SigningPaths(t *testing.T) {
	key, cert := testSigningMaterial(t)
	builder := &samlBuilderUseCase{}

	cases := []struct {
		name string
		raw  []byte
	}{
		{"assertion", []byte(assertionFixtureXML("_a-assertion"))},
		{"response", newResponseWithAssertion(t, "_a-response", []byte(assertionFixtureXML("_a-inner")))},
		{"logout_response", []byte(logoutResponseFixtureXML("_a-logout"))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signed, err := builder.signElementXML(tc.raw, key, cert)
			require.NoError(t, err)
			root := parseSigned(t, signed)

			ok, observed, sigCount := signatureImmediatelyAfterIssuer(root)
			assert.Truef(t, ok,
				"exactly one ds:Signature must appear immediately after Issuer (sigCount=%d, observed order=%v)",
				sigCount, observed)

			violations := collectOrderViolations(root)
			assert.Emptyf(t, violations, "SAML 2.0 content-model order violations: %v", violations)

			value, present, keyInfoOrder := keyName(root)
			if assert.Truef(t, present, "ds:KeyName must be present in KeyInfo (observed KeyInfo children=%v)", keyInfoOrder) {
				assert.Equalf(t, cert.Subject.String(), value, "ds:KeyName must equal the signing certificate subject")
			}

			assert.NoErrorf(t, verifyEnveloped(root, cert), "signature must verify cryptographically against the signing cert")
		})
	}
}

// ---------------------------------------------------------------------------
// T-B: nested signatures — MANDATORY, HIGHEST PRIORITY.
// Sign an Assertion, embed it in a Response, sign the Response. Verify the outer
// signature, then extract the inner Assertion and verify it independently.
// ---------------------------------------------------------------------------

func TestSAMLStrict_B_NestedSignatures(t *testing.T) {
	key, cert := testSigningMaterial(t)
	builder := &samlBuilderUseCase{}

	signedAssertion, err := builder.signElementXML([]byte(assertionFixtureXML("_b-assertion")), key, cert)
	require.NoError(t, err)

	innerRoot := parseSigned(t, signedAssertion)
	okInner, obsInner, cntInner := signatureImmediatelyAfterIssuer(innerRoot)
	assert.Truef(t, okInner,
		"inner Assertion ds:Signature must appear immediately after Issuer (sigCount=%d, observed order=%v)",
		cntInner, obsInner)

	signedResponse, err := builder.signElementXML(
		newResponseWithAssertion(t, "_b-response", signedAssertion), key, cert)
	require.NoError(t, err)

	respRoot := parseSigned(t, signedResponse)
	okOuter, obsOuter, cntOuter := signatureImmediatelyAfterIssuer(respRoot)
	assert.Truef(t, okOuter,
		"outer Response ds:Signature must appear immediately after Issuer (sigCount=%d, observed order=%v)",
		cntOuter, obsOuter)

	// The outer Response signature must verify.
	assert.NoErrorf(t, verifyEnveloped(respRoot, cert), "outer Response signature must verify")

	// Extract the nested Assertion and verify it independently. Because the
	// Response digest covers the Assertion's ds:Signature subtree, any
	// post-signing manipulation reaching the nested SignatureValue or
	// X509Certificate would break the outer digest; both verifications passing
	// is what proves the nested signature survived embedding and extraction.
	inner := directChild(respRoot, nsSAML, "Assertion")
	require.NotNil(t, inner, "embedded Assertion must be present in the signed Response")
	assert.NoErrorf(t, verifyEnveloped(inner.Copy(), cert),
		"nested Assertion signature must verify independently after extraction")
}

// ---------------------------------------------------------------------------
// T-C: negative controls. Each mutation must FAIL cryptographic verification.
// If any passes, the harness has no teeth.
// ---------------------------------------------------------------------------

func TestSAMLStrict_C_NegativeControls(t *testing.T) {
	key, cert := testSigningMaterial(t)
	builder := &samlBuilderUseCase{}

	t.Run("status_code_mutated_after_signing", func(t *testing.T) {
		signed, err := builder.signElementXML(
			newResponseWithAssertion(t, "_c-status", []byte(assertionFixtureXML("_c-status-inner"))), key, cert)
		require.NoError(t, err)
		root := parseSigned(t, signed)
		statusCode := descend(root, [2]string{nsSAMLP, "Status"}, [2]string{nsSAMLP, "StatusCode"})
		require.NotNil(t, statusCode)
		statusCode.CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Requester")
		assert.Error(t, verifyEnveloped(root, cert), "verification must fail after StatusCode mutation")
	})

	t.Run("issuer_text_mutated_after_signing", func(t *testing.T) {
		signed, err := builder.signElementXML([]byte(assertionFixtureXML("_c-issuer")), key, cert)
		require.NoError(t, err)
		root := parseSigned(t, signed)
		issuer := directChild(root, nsSAML, "Issuer")
		require.NotNil(t, issuer)
		issuer.SetText("https://attacker.example.invalid/metadata")
		assert.Error(t, verifyEnveloped(root, cert), "verification must fail after Issuer mutation")
	})

	t.Run("unsigned_assertion_appended_after_signing", func(t *testing.T) {
		signed, err := builder.signElementXML(
			newResponseWithAssertion(t, "_c-append", []byte(assertionFixtureXML("_c-append-inner"))), key, cert)
		require.NoError(t, err)
		root := parseSigned(t, signed)
		injected := etree.NewDocument()
		require.NoError(t, injected.ReadFromString(assertionFixtureXML("_c-injected")))
		root.AddChild(injected.Root().Copy())
		assert.Error(t, verifyEnveloped(root, cert), "verification must fail after appending an unsigned Assertion")
	})
}

// ---------------------------------------------------------------------------
// T-D: CanonicalizationMethod must be exclusive C14N.
// ---------------------------------------------------------------------------

func TestSAMLStrict_D_CanonicalizationMethod(t *testing.T) {
	key, cert := testSigningMaterial(t)
	builder := &samlBuilderUseCase{}

	signed, err := builder.signElementXML([]byte(assertionFixtureXML("_d-assertion")), key, cert)
	require.NoError(t, err)
	root := parseSigned(t, signed)

	alg := canonicalizationAlgorithm(root)
	assert.Equalf(t, exclusiveC14N, alg,
		"CanonicalizationMethod Algorithm must be exclusive C14N (observed=%q)", alg)
}

// ---------------------------------------------------------------------------
// T-E: SignatureMethod must be rsa-sha256 and DigestMethod must be #sha256.
// Guards against a silent SHA-1 downgrade via a dependency bump.
// ---------------------------------------------------------------------------

func TestSAMLStrict_E_SignatureAndDigestAlgorithms(t *testing.T) {
	key, cert := testSigningMaterial(t)
	builder := &samlBuilderUseCase{}

	signed, err := builder.signElementXML([]byte(assertionFixtureXML("_e-assertion")), key, cert)
	require.NoError(t, err)
	root := parseSigned(t, signed)

	sigMethod := signatureMethodAlgorithm(root)
	digestMethod := digestMethodAlgorithm(root)

	assert.Truef(t, strings.HasSuffix(sigMethod, "rsa-sha256"),
		"SignatureMethod Algorithm must end in rsa-sha256 (observed=%q)", sigMethod)
	assert.Truef(t, strings.HasSuffix(digestMethod, "#sha256"),
		"Reference DigestMethod Algorithm must end in #sha256 (observed=%q)", digestMethod)
}

// ---------------------------------------------------------------------------
// QName-value namespace resolution helpers.
//
// XML rules: an UNPREFIXED attribute is in no namespace (the default xmlns
// applies to elements, never to attributes). A prefixed name — on an attribute
// or inside a QName-valued attribute — is only meaningful if its prefix resolves
// to an in-scope xmlns binding on the element or an ancestor.
// ---------------------------------------------------------------------------

const xmlSchemaInstanceNS = "http://www.w3.org/2001/XMLSchema-instance"

func walkElements(root *etree.Element, fn func(*etree.Element)) {
	fn(root)
	for _, c := range root.ChildElements() {
		walkElements(c, fn)
	}
}

func findFirstElement(root *etree.Element, local string) *etree.Element {
	var found *etree.Element
	walkElements(root, func(el *etree.Element) {
		if found == nil && el.Tag == local {
			found = el
		}
	})
	return found
}

// resolvePrefix resolves an xmlns prefix to its namespace URI using the xmlns
// declarations in scope at el or any ancestor. An empty prefix resolves the
// default namespace declaration.
func resolvePrefix(el *etree.Element, prefix string) (string, bool) {
	for cur := el; cur != nil; cur = cur.Parent() {
		for _, a := range cur.Attr {
			if prefix == "" {
				if a.Space == "" && a.Key == "xmlns" {
					return a.Value, true
				}
			} else if a.Space == "xmlns" && a.Key == prefix {
				return a.Value, true
			}
		}
	}
	return "", false
}

// inScopePrefixes returns every xmlns binding visible at el (nearest declaration
// wins). The default namespace, if any, is keyed by the empty string.
func inScopePrefixes(el *etree.Element) map[string]string {
	var chain []*etree.Element
	for cur := el; cur != nil; cur = cur.Parent() {
		chain = append(chain, cur)
	}
	bindings := map[string]string{}
	for i := len(chain) - 1; i >= 0; i-- {
		for _, a := range chain[i].Attr {
			switch {
			case a.Space == "xmlns":
				bindings[a.Key] = a.Value
			case a.Space == "" && a.Key == "xmlns":
				bindings[""] = a.Value
			}
		}
	}
	return bindings
}

func sortedPrefixKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func splitQName(value string) (prefix, local string, hasPrefix bool) {
	if i := strings.IndexByte(value, ':'); i >= 0 {
		return value[:i], value[i+1:], true
	}
	return "", value, false
}

// ---------------------------------------------------------------------------
// T-F: characterization test for a KNOWN, DEFERRED DEFECT.
//
// GenerateSAMLResponse marshals AttributeValue via encoding/xml
// (saml_builder_usecase.go:695). Go emits xsi:type="xs:string" but declares only
// the XMLSchema-instance namespace (as the auto-prefix "_XMLSchema-instance",
// which names the type attribute); it never declares xmlns:xs. The "xs" in the
// value is therefore a dangling QName: namespace-correct on the attribute name,
// unresolvable on its value. The defect is signature-neutral (it does not affect
// the digest or verification) and has been deferred by master decision because no
// partner is currently known to be blocked by it.
//
// This test is INVERTED on purpose: it REQUIRES the known dangling QName to be
// present, so the package stays green while the defect is documented and any
// change to it trips loudly. It reuses the exact detection logic (walker, prefix
// resolution, in-scope collection) of the real assertion.
// ---------------------------------------------------------------------------

func TestSAMLStrict_F_KnownDefect_DanglingQNameAttribute(t *testing.T) {
	key, cert := testSigningMaterial(t)
	builder := &samlBuilderUseCase{}

	signed, err := builder.signElementXML([]byte(assertionFixtureXML("_f-assertion")), key, cert)
	require.NoError(t, err)
	root := parseSigned(t, signed)

	var violations []string
	walkElements(root, func(el *etree.Element) {
		for _, a := range el.Attr {
			// xsi:type is a prefixed attribute; unprefixed attributes are
			// namespaceless and cannot be the {XMLSchema-instance}type attribute.
			if a.Space == "" || a.Key != "type" {
				continue
			}
			ns, ok := resolvePrefix(el, a.Space)
			if !ok || ns != xmlSchemaInstanceNS {
				continue
			}
			prefix, _, hasPrefix := splitQName(a.Value)
			if !hasPrefix {
				continue
			}
			if _, bound := resolvePrefix(el, prefix); !bound {
				violations = append(violations, fmt.Sprintf(
					"element <%s>: xsi:type value %q references prefix %q which is not in scope; in-scope prefixes: %v",
					qname(el), a.Value, prefix, sortedPrefixKeys(inScopePrefixes(el))))
			}
		}
	})

	const knownDefect = "this test asserts a KNOWN DEFECT: an xsi:type value carrying a " +
		"dangling \"xs\" QName. If it fails, the defect has changed or been fixed — verify " +
		"the fix, then invert this test back into a real assertion (absence of dangling " +
		"QNames) and rename it. Do not delete it."

	// The known defect must still be present.
	require.NotEmptyf(t, violations, "%s (no dangling QName-valued attribute found)", knownDefect)

	// And it must be exactly the known one: a dangling "xs" prefix.
	foundXSDangling := false
	for _, v := range violations {
		if strings.Contains(v, `prefix "xs"`) {
			foundXSDangling = true
			break
		}
	}
	assert.Truef(t, foundXSDangling, "%s (dangling QNames found, but none for prefix \"xs\": %v)", knownDefect, violations)
}

// ---------------------------------------------------------------------------
// T-G: xsi:type is namespace-correct.
// Independently of the prefix literal, the type attribute must resolve to the
// XMLSchema-instance namespace. This must PASS today (the auto-generated
// "_XMLSchema-instance" prefix is namespace-correct) and keep passing after any
// future prefix normalisation. It pins the invariant, not the cosmetics.
// ---------------------------------------------------------------------------

func TestSAMLStrict_G_XSITypeNamespaceCorrect(t *testing.T) {
	key, cert := testSigningMaterial(t)
	builder := &samlBuilderUseCase{}

	signed, err := builder.signElementXML([]byte(assertionFixtureXML("_g-assertion")), key, cert)
	require.NoError(t, err)
	root := parseSigned(t, signed)

	av := findFirstElement(root, "AttributeValue")
	require.NotNil(t, av, "signed assertion must contain an AttributeValue")

	prefix := ""
	found := false
	for _, a := range av.Attr {
		if a.Key == "type" && a.Space != "" {
			prefix = a.Space
			found = true
			break
		}
	}
	require.Truef(t, found, "AttributeValue must carry a prefixed type attribute")

	ns, ok := resolvePrefix(av, prefix)
	require.Truef(t, ok, "type attribute prefix %q must resolve to a namespace", prefix)
	assert.Equalf(t, xmlSchemaInstanceNS, ns,
		"type attribute (prefix %q) must resolve to the XMLSchema-instance namespace", prefix)
}

// ---------------------------------------------------------------------------
// T-H: QName binding diagnostic (non-asserting).
// Reports the xmlns bindings in scope on the signed Assertion root and the
// literal prefix used for the type attribute, to feed the follow-up work order.
// ---------------------------------------------------------------------------

func TestSAMLStrict_H_QNameBindingDiagnostic(t *testing.T) {
	key, cert := testSigningMaterial(t)
	builder := &samlBuilderUseCase{}

	signed, err := builder.signElementXML([]byte(assertionFixtureXML("_h-assertion")), key, cert)
	require.NoError(t, err)
	root := parseSigned(t, signed)

	t.Logf("xmlns bindings in scope on signed Assertion root: %v", inScopePrefixes(root))

	av := findFirstElement(root, "AttributeValue")
	if av == nil {
		t.Log("no AttributeValue element found in signed output")
		return
	}
	for _, a := range av.Attr {
		if a.Key == "type" && a.Space != "" {
			ns, ok := resolvePrefix(av, a.Space)
			t.Logf("type attribute literal prefix: %q (resolves=%v, namespace=%q)", a.Space, ok, ns)
			t.Logf("type attribute value (QName): %q", a.Value)
		}
	}
	t.Logf("xmlns bindings in scope on the AttributeValue element: %v", inScopePrefixes(av))
}
