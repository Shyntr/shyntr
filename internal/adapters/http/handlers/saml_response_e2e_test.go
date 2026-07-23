package handlers_test

// SAML Response acceptance gate — the HTTP-boundary layer.
//
// The existing gate (internal/application/usecase/saml_strict_test.go) drives
// signElementXML directly against hand-built fixtures. It cannot observe anything
// GenerateSAMLResponse does: timestamp handling, NameID-format resolution,
// attribute construction, encryption, or which certificate is actually used.
//
// This gate drives the REAL IdP SSO HTTP endpoint end to end (routing → handler →
// use case → signing), takes the SAMLResponse from the auto-post form the handler
// renders, base64-decodes it and parses it with etree, then asserts the structural
// and cryptographic properties of production output. Structural checks are reused
// from internal/testsupport/samlxml (single source of truth). Signature checks use
// real key material and real goxmldsig verification — nothing is stubbed.
//
// Known, tracked defects (timestamp precision, NameID format, attribute
// NameFormat, the dangling xs: QName) are NOT asserted here; they are captured in
// the non-asserting diagnostic and will each land with their own assertion.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/testsupport/samlxml"
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

// e2eFixedClock pins the SAML builder's issuance clock so timestamps are
// deterministic. Certificate validity stays on the real wall clock (out of scope
// of the injected clock), so goxmldsig verification is unaffected.
func e2eFixedClock() time.Time {
	return time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
}

// verifyXMLSignature performs real enveloped-signature verification with the IdP
// certificate as the only trust root. It returns nil only when the signature is
// cryptographically valid. findSignature selects the signature whose Reference
// matches the passed element's ID, so it verifies the outer Response or an
// extracted inner Assertion correctly.
func verifyXMLSignature(el *etree.Element, cert *x509.Certificate) error {
	store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	ctx := dsig.NewDefaultValidationContext(store)
	ctx.IdAttribute = "ID"
	_, err := ctx.Validate(el)
	return err
}

// idpSigningCert returns the certificate the IdP actually holds for its active
// "sig" key — the stored certificate, not an ephemeral one.
func idpSigningCert(t *testing.T, env *oidcE2EEnv) *x509.Certificate {
	t.Helper()
	_, cert, _, err := env.keyMgr.GetActiveKeys(context.Background(), "sig")
	require.NoError(t, err)
	require.NotNil(t, cert, "IdP must hold a stored signing certificate")
	return cert
}

func generateSPCertPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "sp.example.test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// createE2ESAMLClient registers a SAML SP with exact signing/encryption flags.
// The encryption target is SPEncryptionCertificate, not SPCertificate: setting
// SPCertificate would make ParseAuthnRequest require a signed AuthnRequest (these
// tests send unsigned ones), unrelated to assertion encryption.
func createE2ESAMLClient(t *testing.T, env *oidcE2EEnv, clientID, entityID, acsURL string,
	signResponse, signAssertion, encryptAssertion bool, spEncCertPEM string) {
	t.Helper()
	require.NoError(t, env.db.Create(&models.SAMLClientGORM{
		ID:                      clientID,
		TenantID:                "tenant-a",
		Name:                    "E2E SP " + clientID,
		EntityID:                entityID,
		ACSURL:                  acsURL,
		SPEncryptionCertificate: spEncCertPEM,
		AllowedScopes:           []string{"openid", "profile"},
		Active:                  true,
	}).Error)
	// Force the boolean flags explicitly; GORM's `default:true` tags would
	// otherwise override a zero-value (false) on insert.
	require.NoError(t, env.db.Model(&models.SAMLClientGORM{}).Where("id = ?", clientID).
		Updates(map[string]interface{}{
			"sign_response":     signResponse,
			"sign_assertion":    signAssertion,
			"encrypt_assertion": encryptAssertion,
		}).Error)
}

// buildAuthnRequestXML builds an AuthnRequest with Issuer and optional extra
// children (e.g. a NameIDPolicy) inserted after Issuer.
func buildAuthnRequestXML(entityID, acsURL, extraChildren string) string {
	return fmt.Sprintf(
		`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="e2e-req-%d" Version="2.0" IssueInstant="2026-01-02T03:04:05Z" AssertionConsumerServiceURL="%s"><saml:Issuer>%s</saml:Issuer>%s</samlp:AuthnRequest>`,
		time.Now().UnixNano(), acsURL, entityID, extraChildren)
}

// startE2EIdPSSO drives the initial IdP SSO request and returns the login challenge.
func startE2EIdPSSO(t *testing.T, env *oidcE2EEnv, authnRequestXML string) string {
	t.Helper()
	samlRequest := encodeRedirectBindingSAMLRequest(t, authnRequestXML)
	resp := serveRequest(t, env.router, http.MethodGet,
		"/t/tenant-a/saml/idp/sso?SAMLRequest="+url.QueryEscape(samlRequest)+"&RelayState="+url.QueryEscape("relay-e2e-gate"),
		nil, nil)
	require.Equal(t, http.StatusFound, resp.Code)
	challenge := parseLocationQuery(t, resp.Header().Get("Location")).Get("login_challenge")
	require.NotEmpty(t, challenge)
	return challenge
}

// acceptE2ESAMLLogin performs the admin login accept and returns redirect_to (the
// login_verifier URL). Synthetic identity only; example.test hostnames.
func acceptE2ESAMLLogin(t *testing.T, env *oidcE2EEnv, loginChallenge string) string {
	t.Helper()
	loginPayload := []byte(`{
		"subject": "ext-subject@example.test",
		"remember": true,
		"remember_for": 3600,
		"context": {
			"identity": {
				"attributes": {
					"preferred_username": "alice",
					"email": "alice@example.test",
					"name": "Alice Example",
					"given_name": "Alice",
					"family_name": "Example"
				},
				"groups": ["engineering"],
				"roles": ["admin"]
			},
			"authentication": {"amr": ["pwd"]}
		}
	}`)
	resp := serveRequest(t, env.router, http.MethodPut,
		"/admin/login/accept?login_challenge="+url.QueryEscape(loginChallenge), bytes.NewReader(loginPayload), nil)
	require.Equal(t, http.StatusOK, resp.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.NotEmpty(t, body["redirect_to"])
	return body["redirect_to"]
}

// followE2ERedirect issues a GET to the login_verifier URL and returns the raw
// recorder, without asserting its status (callers assert success or failure).
func followE2ERedirect(t *testing.T, env *oidcE2EEnv, redirectTo string) *httptest.ResponseRecorder {
	t.Helper()
	u, err := url.Parse(redirectTo)
	require.NoError(t, err)
	return serveRequest(t, env.router, http.MethodGet, u.RequestURI(), nil, nil)
}

// parseE2ESAMLResponse requires an OK response, decodes the SAMLResponse from the
// auto-post form, and returns the parsed Response root element.
func parseE2ESAMLResponse(t *testing.T, resp *httptest.ResponseRecorder) *etree.Element {
	t.Helper()
	require.Equal(t, http.StatusOK, resp.Code)
	responseXML := decodeSAMLResponseXML(t, resp.Body.String())
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(responseXML))
	root := doc.Root()
	require.NotNil(t, root)
	return root
}

// driveIdPSSOResponseWithChildren drives the full IdP SSO flow with optional extra
// AuthnRequest children and returns the parsed Response root element.
func driveIdPSSOResponseWithChildren(t *testing.T, env *oidcE2EEnv, clientID, entityID, acsURL string,
	signResponse, signAssertion, encryptAssertion bool, spCertPEM, extraAuthnReqChildren string) *etree.Element {
	t.Helper()
	createE2ESAMLClient(t, env, clientID, entityID, acsURL, signResponse, signAssertion, encryptAssertion, spCertPEM)
	challenge := startE2EIdPSSO(t, env, buildAuthnRequestXML(entityID, acsURL, extraAuthnReqChildren))
	redirectTo := acceptE2ESAMLLogin(t, env, challenge)
	return parseE2ESAMLResponse(t, followE2ERedirect(t, env, redirectTo))
}

// driveIdPSSOResponse drives the flow with no extra AuthnRequest children.
func driveIdPSSOResponse(t *testing.T, env *oidcE2EEnv, clientID, entityID, acsURL string,
	signResponse, signAssertion, encryptAssertion bool, spCertPEM string) *etree.Element {
	t.Helper()
	return driveIdPSSOResponseWithChildren(t, env, clientID, entityID, acsURL,
		signResponse, signAssertion, encryptAssertion, spCertPEM, "")
}

// C1: an AuthnRequest carrying a NameIDPolicy now reaches GenerateSAMLResponse
// intact. Observable proof: requesting emailAddress makes the emitted NameID
// Format emailAddress with the user's email as its value. Before this fix the
// handler discarded NameIDPolicy, so the output fell back to the default format.
// (C2 — ForceAuthn survival — is NOT asserted: GenerateSAMLResponse does not act
// on ForceAuthn, so it has no observable effect in the emitted assertion at this
// commit. It is carried through the parsed request but cannot be observed without
// inspecting internals.)
func TestSAMLResponseE2E_C1_NameIDPolicyReachesUseCase(t *testing.T) {
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	nameIDPolicy := `<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>`
	root := driveIdPSSOResponseWithChildren(t, env, "e2e-c1", "http://sp.example.test/c1", "http://sp.example.test/acs",
		true, false, false, "", nameIDPolicy)

	assertion := samlxml.DirectChild(root, samlxml.NSSAML, "Assertion")
	require.NotNil(t, assertion, "a successful login must emit an Assertion")
	subject := samlxml.DirectChild(assertion, samlxml.NSSAML, "Subject")
	require.NotNil(t, subject)
	nameID := samlxml.DirectChild(subject, samlxml.NSSAML, "NameID")
	require.NotNil(t, nameID)

	require.Equal(t, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", nameID.SelectAttrValue("Format", ""),
		"the requested NameIDPolicy emailAddress format must survive to GenerateSAMLResponse")
	require.Equal(t, "alice@example.test", nameID.Text(),
		"the emailAddress NameID value must be the user's email")
}

// C3: a malformed stored AuthnRequest must fail closed — an error response, not a
// successful login using SP defaults. MUST have teeth.
func TestSAMLResponseE2E_C3_MalformedStoredRequestFailsClosed(t *testing.T) {
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	createE2ESAMLClient(t, env, "e2e-c3", "http://sp.example.test/c3", "http://sp.example.test/acs",
		true, false, false, "")
	challenge := startE2EIdPSSO(t, env, buildAuthnRequestXML("http://sp.example.test/c3", "http://sp.example.test/acs", ""))
	redirectTo := acceptE2ESAMLLogin(t, env, challenge)

	// Corrupt the stored AuthnRequest so it can no longer be parsed. A fail-open
	// handler would swallow the parse error and issue an assertion using SP
	// defaults; a fail-closed handler must return an error and emit no assertion.
	malformed := base64.StdEncoding.EncodeToString([]byte("this is not a valid SAML AuthnRequest"))
	corruptURL := fmt.Sprintf("%s/t/tenant-a/saml/idp/sso?SAMLRequest=%s&RelayState=relay-e2e-gate",
		env.cfg.BaseIssuerURL, url.QueryEscape(malformed))
	require.NoError(t, env.db.Model(&models.LoginRequestGORM{}).Where("id = ?", challenge).
		Update("request_url", corruptURL).Error)

	resp := followE2ERedirect(t, env, redirectTo)

	require.NotEqualf(t, http.StatusOK, resp.Code,
		"a malformed stored AuthnRequest must not yield a successful login (got %d)", resp.Code)
	require.Equal(t, http.StatusBadRequest, resp.Code,
		"a malformed stored AuthnRequest must produce a client error")
	require.NotContains(t, resp.Body.String(), "SAMLResponse",
		"no SAMLResponse (assertion) may be emitted on the fail-closed path")
}

// A1: signed Response — valid content model, one ds:Signature after Issuer, and a
// signature that verifies against the IdP certificate.
func TestSAMLResponseE2E_A1_SignedResponse(t *testing.T) {
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	root := driveIdPSSOResponse(t, env, "e2e-a1", "http://sp.example.test/a1", "http://sp.example.test/acs",
		true, false, false, "")

	require.Empty(t, samlxml.CollectOrderViolations(root), "Response content-model order must be valid")

	ok, observed, sigCount := samlxml.SignatureImmediatelyAfterIssuer(root)
	require.Truef(t, ok, "exactly one ds:Signature must appear immediately after Issuer (sigCount=%d, observed order=%v)", sigCount, observed)

	require.NoError(t, verifyXMLSignature(root, idpSigningCert(t, env)),
		"Response signature must verify against the IdP certificate")
}

// A2: nested signatures in production output — outer Response verifies; inner
// Assertion, extracted independently, has correct placement and verifies.
func TestSAMLResponseE2E_A2_NestedSignatures(t *testing.T) {
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	cert := idpSigningCert(t, env)
	root := driveIdPSSOResponse(t, env, "e2e-a2", "http://sp.example.test/a2", "http://sp.example.test/acs",
		true, true, false, "")

	require.NoError(t, verifyXMLSignature(root, cert), "outer Response signature must verify")

	inner := samlxml.DirectChild(root, samlxml.NSSAML, "Assertion")
	require.NotNil(t, inner, "signed Response must contain a plaintext Assertion")

	ok, observed, sigCount := samlxml.SignatureImmediatelyAfterIssuer(inner)
	require.Truef(t, ok, "inner Assertion ds:Signature must appear immediately after Issuer (sigCount=%d, observed order=%v)", sigCount, observed)

	require.NoError(t, verifyXMLSignature(inner.Copy(), cert),
		"inner Assertion signature must verify independently after extraction")
}

// A3: ds:KeyName equals the Subject DN of the certificate the IdP actually holds
// (the stored cert), and that same cert verifies the signature — proving the
// stored-certificate fix at the HTTP boundary.
func TestSAMLResponseE2E_A3_KeyNameIsStoredCertificateSubject(t *testing.T) {
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	cert := idpSigningCert(t, env)
	root := driveIdPSSOResponse(t, env, "e2e-a3", "http://sp.example.test/a3", "http://sp.example.test/acs",
		true, false, false, "")

	value, present, keyInfoOrder := samlxml.KeyName(root)
	require.Truef(t, present, "ds:KeyName must be present in KeyInfo (observed KeyInfo children=%v)", keyInfoOrder)
	require.Equal(t, cert.Subject.String(), value,
		"ds:KeyName must equal the Subject DN of the IdP's stored certificate")

	require.NoError(t, verifyXMLSignature(root, cert),
		"the same stored certificate must verify the Response signature")
}

// A4: encrypted assertion — Response carries EncryptedAssertion (not Assertion),
// the content model is still valid, and the Response signature still verifies.
func TestSAMLResponseE2E_A4_EncryptedAssertion(t *testing.T) {
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	cert := idpSigningCert(t, env)
	root := driveIdPSSOResponse(t, env, "e2e-a4", "http://sp.example.test/a4", "http://sp.example.test/acs",
		true, false, true, generateSPCertPEM(t))

	require.NotNil(t, samlxml.DirectChild(root, samlxml.NSSAML, "EncryptedAssertion"),
		"Response must carry an EncryptedAssertion")
	require.Nil(t, samlxml.DirectChild(root, samlxml.NSSAML, "Assertion"),
		"Response must not carry a plaintext Assertion when encryption is enabled")

	require.Empty(t, samlxml.CollectOrderViolations(root),
		"content-model order must remain valid with EncryptedAssertion")

	require.NoError(t, verifyXMLSignature(root, cert),
		"Response signature must still verify over the encrypted assertion")
}

// assertMillisecondTimestamp asserts a serialized xs:dateTime carries at most
// three fractional-second digits and equals the expected millisecond-truncated
// instant.
func assertMillisecondTimestamp(t *testing.T, label, serialized string, expected time.Time) {
	t.Helper()
	require.NotEmptyf(t, serialized, "%s must be present", label)
	if dot := strings.IndexByte(serialized, '.'); dot >= 0 {
		frac := serialized[dot+1:]
		if z := strings.IndexAny(frac, "Z+-"); z >= 0 {
			frac = frac[:z]
		}
		require.LessOrEqualf(t, len(frac), 3,
			"%s: %q carries more than three fractional-second digits", label, serialized)
	}
	parsed, err := time.Parse(time.RFC3339Nano, serialized)
	require.NoErrorf(t, err, "%s: cannot parse %q", label, serialized)
	require.Truef(t, parsed.Equal(expected),
		"%s: got %q, want millisecond-truncated %q", label, serialized, expected.Format(time.RFC3339Nano))
}

// Timestamp truncation: every SAML issuance timestamp must be millisecond
// precision. The clock deliberately carries a nanosecond component (123456789ns)
// that is not a whole millisecond, so an untruncated value would serialize with
// more than three fractional digits and fail this test.
func TestSAMLResponseE2E_IssuanceTimestampsTruncatedToMillisecond(t *testing.T) {
	base := time.Date(2026, time.January, 2, 3, 4, 5, 123456789, time.UTC)
	expectedNow := base.Truncate(time.Millisecond) // 2026-01-02T03:04:05.123Z

	env := setupOIDCE2EEnvWithClock(t, func() time.Time { return base })
	root := driveIdPSSOResponse(t, env, "e2e-ts", "http://sp.example.test/ts", "http://sp.example.test/acs",
		true, false, false, "")

	assertion := samlxml.DirectChild(root, samlxml.NSSAML, "Assertion")
	require.NotNil(t, assertion, "signed Response must contain a plaintext Assertion")
	conditions := samlxml.DirectChild(assertion, samlxml.NSSAML, "Conditions")
	require.NotNil(t, conditions)
	subject := samlxml.DirectChild(assertion, samlxml.NSSAML, "Subject")
	require.NotNil(t, subject)
	scd := samlxml.Descend(subject,
		[2]string{samlxml.NSSAML, "SubjectConfirmation"},
		[2]string{samlxml.NSSAML, "SubjectConfirmationData"})
	require.NotNil(t, scd)
	authnStmt := samlxml.DirectChild(assertion, samlxml.NSSAML, "AuthnStatement")
	require.NotNil(t, authnStmt)

	assertMillisecondTimestamp(t, "Response IssueInstant", root.SelectAttrValue("IssueInstant", ""), expectedNow)
	assertMillisecondTimestamp(t, "Assertion IssueInstant", assertion.SelectAttrValue("IssueInstant", ""), expectedNow)
	assertMillisecondTimestamp(t, "Conditions NotBefore", conditions.SelectAttrValue("NotBefore", ""), expectedNow.Add(-5*time.Minute))
	assertMillisecondTimestamp(t, "Conditions NotOnOrAfter", conditions.SelectAttrValue("NotOnOrAfter", ""), expectedNow.Add(5*time.Minute))
	assertMillisecondTimestamp(t, "SubjectConfirmationData NotOnOrAfter", scd.SelectAttrValue("NotOnOrAfter", ""), expectedNow.Add(5*time.Minute))
	assertMillisecondTimestamp(t, "AuthnStatement AuthnInstant", authnStmt.SelectAttrValue("AuthnInstant", ""), expectedNow)
}

// A5: the CanonicalizationMethod in real output is exclusive C14N.
func TestSAMLResponseE2E_A5_ExclusiveCanonicalization(t *testing.T) {
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	root := driveIdPSSOResponse(t, env, "e2e-a5", "http://sp.example.test/a5", "http://sp.example.test/acs",
		true, false, false, "")

	cm := samlxml.Descend(root,
		[2]string{samlxml.NSDS, "Signature"},
		[2]string{samlxml.NSDS, "SignedInfo"},
		[2]string{samlxml.NSDS, "CanonicalizationMethod"})
	require.NotNil(t, cm, "CanonicalizationMethod must be present")
	require.Equal(t, "http://www.w3.org/2001/10/xml-exc-c14n#", cm.SelectAttrValue("Algorithm", ""),
		"CanonicalizationMethod must be exclusive C14N in production output")
}

// Diagnostic (non-asserting): reports the timestamps, NameID format/value and
// per-Attribute NameFormat of real output, to feed the next work orders. It emits
// timestamps, formats and attribute NAMES only — never attribute values or the
// assertion body.
func TestSAMLResponseE2E_Diagnostic_TimestampsFormatsAttributeNames(t *testing.T) {
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	root := driveIdPSSOResponse(t, env, "e2e-diag", "http://sp.example.test/diag", "http://sp.example.test/acs",
		true, true, false, "")

	t.Logf("Response IssueInstant: %q", root.SelectAttrValue("IssueInstant", ""))

	assertion := samlxml.DirectChild(root, samlxml.NSSAML, "Assertion")
	require.NotNil(t, assertion, "diagnostic needs a plaintext Assertion")
	t.Logf("Assertion IssueInstant: %q", assertion.SelectAttrValue("IssueInstant", ""))

	if conditions := samlxml.DirectChild(assertion, samlxml.NSSAML, "Conditions"); conditions != nil {
		t.Logf("Conditions NotBefore: %q", conditions.SelectAttrValue("NotBefore", ""))
		t.Logf("Conditions NotOnOrAfter: %q", conditions.SelectAttrValue("NotOnOrAfter", ""))
	}

	if subject := samlxml.DirectChild(assertion, samlxml.NSSAML, "Subject"); subject != nil {
		if nameID := samlxml.DirectChild(subject, samlxml.NSSAML, "NameID"); nameID != nil {
			t.Logf("NameID Format (no NameIDPolicy in request): %q", nameID.SelectAttrValue("Format", ""))
			t.Logf("NameID value: %q", nameID.Text())
		}
		if sc := samlxml.DirectChild(subject, samlxml.NSSAML, "SubjectConfirmation"); sc != nil {
			if scd := samlxml.DirectChild(sc, samlxml.NSSAML, "SubjectConfirmationData"); scd != nil {
				t.Logf("SubjectConfirmationData NotOnOrAfter: %q", scd.SelectAttrValue("NotOnOrAfter", ""))
			}
		}
	}

	if authnStmt := samlxml.DirectChild(assertion, samlxml.NSSAML, "AuthnStatement"); authnStmt != nil {
		t.Logf("AuthnStatement AuthnInstant: %q", authnStmt.SelectAttrValue("AuthnInstant", ""))
	}

	if attrStmt := samlxml.DirectChild(assertion, samlxml.NSSAML, "AttributeStatement"); attrStmt != nil {
		for _, attr := range attrStmt.ChildElements() {
			if attr.Tag == "Attribute" {
				t.Logf("Attribute %q NameFormat: %q", attr.SelectAttrValue("Name", ""), attr.SelectAttrValue("NameFormat", ""))
			}
		}
	}

	// LogoutResponse IssueInstant is produced by GenerateLogoutResponse via the
	// IdP SLO endpoint (a separate flow this SSO-driven gate does not exercise),
	// so it is not reachable here without adding a new flow. It uses the same
	// s.now().Truncate(time.Millisecond) source as GenerateSAMLResponse.
	t.Log("LogoutResponse IssueInstant: not reachable from this SSO-driven gate (produced by the IdP SLO flow)")
}
