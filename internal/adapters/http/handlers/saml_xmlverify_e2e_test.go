package handlers_test

// Independent SAML verification harness.
//
// The Go-native gate (saml_response_e2e_test.go) verifies signatures with
// goxmldsig — the same library that produced them — and checks structure against
// a hand-written content model. Both sides share code, so a non-standard library
// behaviour would be invisible. This file closes that gap: it validates the real
// signed Response with EXTERNAL tools that share no code with the signer —
// xmllint (XSD structure) and xmlsec1 (signature) — and against the vendored
// normative OASIS/W3C schemas in testdata/saml/.
//
// When a tool is absent the test SKIPs loudly, unless SHYNTR_REQUIRE_XML_TOOLS is
// set (CI), in which case it FAILs. Temp files use t.TempDir() (0700, auto-removed)
// with 0600 files; no private key or plaintext assertion is left on disk or logged.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/testsupport/samlxml"
	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

const (
	schemaDir     = "testdata/saml"
	protocolXSD   = schemaDir + "/saml-schema-protocol-2.0.xsd"
	assertionXSD  = schemaDir + "/saml-schema-assertion-2.0.xsd"
	nsProtoResp   = "urn:oasis:names:tc:SAML:2.0:protocol:Response"
	nsAssertion   = "urn:oasis:names:tc:SAML:2.0:assertion:Assertion"
	xmlSchemaNS   = "http://www.w3.org/2001/XMLSchema"
	statusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
	statusReq     = "urn:oasis:names:tc:SAML:2.0:status:Requester"
)

// requireXMLTool ensures a CLI tool is present. Absent => SKIP (loud), or FAIL
// when SHYNTR_REQUIRE_XML_TOOLS is set.
func requireXMLTool(t *testing.T, name, pkg, verification string) {
	t.Helper()
	if _, err := exec.LookPath(name); err == nil {
		return
	}
	msg := fmt.Sprintf("%q not found (install package %q) — NOT PERFORMED: %s", name, pkg, verification)
	if os.Getenv("SHYNTR_REQUIRE_XML_TOOLS") != "" {
		t.Fatalf("SHYNTR_REQUIRE_XML_TOOLS is set but %s", msg)
	}
	t.Skipf("SKIPPING external XML verification — %s", msg)
}

// writeTemp writes content to a 0600 file under the test's auto-removed TempDir.
func writeTemp(t *testing.T, base string, content []byte) string {
	t.Helper()
	path := t.TempDir() + "/" + base
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

// runCmd runs a command and returns its exit code and combined output.
func runCmd(name string, args ...string) (int, string) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	}
	return -1, string(out)
}

// xmlsec1VerifyArgs is the invocation validated against xmlsec1 1.3.12. Two
// --id-attr entries because the document has two signed elements (Response and
// nested Assertion); --insecure isolates signature validity from X509 policy so a
// self-signed test cert does not fail on chain/trust.
func xmlsec1VerifyArgs(certPath, file string) []string {
	return []string{
		"--verify",
		"--id-attr:ID", nsProtoResp,
		"--id-attr:ID", nsAssertion,
		"--trusted-pem", certPath,
		"--insecure",
		file,
	}
}

// classifyXmlsec1Failure maps xmlsec1 output to one of the three failure modes.
func classifyXmlsec1Failure(out string) string {
	lo := strings.ToLower(out)
	switch {
	case strings.Contains(lo, "usage") || strings.Contains(lo, "unknown option") || strings.Contains(lo, "error: bad"):
		return "malformed-invocation"
	case strings.Contains(lo, "certificate") || strings.Contains(lo, "trust") || strings.Contains(lo, "x509"):
		return "untrusted-certificate"
	case strings.Contains(lo, "reference") || strings.Contains(lo, "signature") || strings.Contains(lo, "digest"):
		return "invalid-signature"
	default:
		return "unknown"
	}
}

// idpCertPEM writes the IdP signing certificate (public) to a temp PEM file.
func idpCertPEM(t *testing.T, env *oidcE2EEnv) string {
	t.Helper()
	cert := idpSigningCert(t, env)
	return writeTemp(t, "idp_cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// driveRawResponse drives the flow and returns the raw decoded Response XML.
func driveRawResponse(t *testing.T, env *oidcE2EEnv, clientID, entityID, acsURL string,
	signResponse, signAssertion, encrypt bool, spEncCertPEM string) string {
	t.Helper()
	createE2ESAMLClient(t, env, clientID, entityID, acsURL, signResponse, signAssertion, encrypt, spEncCertPEM)
	ch := startE2EIdPSSO(t, env, buildAuthnRequestXML(entityID, acsURL, ""))
	resp := followE2ERedirect(t, env, acceptE2ESAMLLogin(t, env, ch))
	require.Equal(t, 200, resp.Code)
	return decodeSAMLResponseXML(t, resp.Body.String())
}

// E1: XSD validation of the Response against the normative protocol schema.
func TestSAMLXMLVerify_E1_ResponseValidatesAgainstXSD(t *testing.T) {
	requireXMLTool(t, "xmllint", "libxml2-utils", "XSD structural validation of the Response")
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	raw := driveRawResponse(t, env, "e2e-e1", "http://sp.example.test/e1", "http://sp.example.test/acs", true, true, false, "")
	file := writeTemp(t, "response.xml", []byte(raw))

	code, out := runCmd("xmllint", "--nonet", "--noout", "--schema", protocolXSD, file)
	require.Equalf(t, 0, code, "Response must validate against the SAML protocol XSD; xmllint output:\n%s", out)
}

// E2: independent signature verification of the Response signature.
func TestSAMLXMLVerify_E2_ResponseSignatureVerifies(t *testing.T) {
	requireXMLTool(t, "xmlsec1", "xmlsec1", "independent Response signature verification")
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	raw := driveRawResponse(t, env, "e2e-e2", "http://sp.example.test/e2", "http://sp.example.test/acs", true, false, false, "")
	file := writeTemp(t, "response.xml", []byte(raw))
	cert := idpCertPEM(t, env)

	code, out := runCmd("xmlsec1", xmlsec1VerifyArgs(cert, file)...)
	require.Equalf(t, 0, code, "Response signature must verify independently (failure mode: %s); xmlsec1 output:\n%s",
		classifyXmlsec1Failure(out), out)
}

// E3: the nested case — outer Response signature and inner Assertion signature
// each verify independently.
func TestSAMLXMLVerify_E3_NestedSignaturesVerify(t *testing.T) {
	requireXMLTool(t, "xmlsec1", "xmlsec1", "independent nested-signature verification")
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	raw := driveRawResponse(t, env, "e2e-e3", "http://sp.example.test/e3", "http://sp.example.test/acs", true, true, false, "")
	cert := idpCertPEM(t, env)

	// Outer Response signature.
	respFile := writeTemp(t, "response.xml", []byte(raw))
	code, out := runCmd("xmlsec1", xmlsec1VerifyArgs(cert, respFile)...)
	require.Equalf(t, 0, code, "outer Response signature must verify (failure mode: %s):\n%s", classifyXmlsec1Failure(out), out)

	// Inner Assertion signature, extracted and verified independently.
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(raw))
	inner := samlxml.DirectChild(doc.Root(), "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")
	require.NotNil(t, inner, "signed Response must contain a plaintext Assertion")
	innerDoc := etree.NewDocument()
	innerDoc.SetRoot(inner.Copy())
	innerBytes, err := innerDoc.WriteToBytes()
	require.NoError(t, err)
	innerFile := writeTemp(t, "assertion.xml", innerBytes)
	code, out = runCmd("xmlsec1", "--verify", "--id-attr:ID", nsAssertion, "--trusted-pem", cert, "--insecure", innerFile)
	require.Equalf(t, 0, code, "inner Assertion signature must verify independently (failure mode: %s):\n%s", classifyXmlsec1Failure(out), out)
}

// E4: negative control — a mutated Status must be REJECTED, and the reason must be
// a signature/digest failure (not a trust failure, not a malformed invocation).
func TestSAMLXMLVerify_E4_MutatedDocumentRejected(t *testing.T) {
	requireXMLTool(t, "xmlsec1", "xmlsec1", "negative-control signature rejection")
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	raw := driveRawResponse(t, env, "e2e-e4", "http://sp.example.test/e4", "http://sp.example.test/acs", true, false, false, "")
	require.Contains(t, raw, statusSuccess, "precondition: the response carries a Success status")
	mutated := strings.Replace(raw, statusSuccess, statusReq, 1)
	require.NotEqual(t, raw, mutated, "mutation must change the document")
	file := writeTemp(t, "mutated.xml", []byte(mutated))
	cert := idpCertPEM(t, env)

	// Identical invocation to E2 (which verifies OK); only the document changed.
	code, out := runCmd("xmlsec1", xmlsec1VerifyArgs(cert, file)...)
	mode := classifyXmlsec1Failure(out)
	require.NotEqualf(t, 0, code, "a mutated document MUST be rejected; xmlsec1 output:\n%s", out)
	// With --insecure, a failure cannot be a trust failure; the invocation is the
	// same one E2 accepts, so it cannot be a usage error. It is a signature/digest
	// failure — assert we did not misclassify it as either of the other two.
	require.NotEqualf(t, "malformed-invocation", mode, "rejection must not be a usage error:\n%s", out)
	require.NotEqualf(t, "untrusted-certificate", mode, "rejection must not be a trust failure (--insecure):\n%s", out)
	t.Logf("E4 rejection classified as: %s\n%s", mode, out)
}

// --- E5: encrypted assertion ---

func generateSPKeyPair(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "sp.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// decryptEncryptedAssertion recovers the plaintext assertion: RSA-OAEP(SHA-1)
// unwraps the AES-256-GCM key, whose ciphertext is nonce||sealed. Mirrors
// encryptAssertionBytes.
func decryptEncryptedAssertion(t *testing.T, enc *etree.Element, spKey *rsa.PrivateKey) []byte {
	t.Helper()
	encData := enc.FindElement("./EncryptedData")
	require.NotNil(t, encData)
	wrapped := encData.FindElement("./KeyInfo/EncryptedKey/CipherData/CipherValue")
	require.NotNil(t, wrapped)
	wrappedBytes, err := base64.StdEncoding.DecodeString(stripWhitespace(wrapped.Text()))
	require.NoError(t, err)
	symKey, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, spKey, wrappedBytes, nil)
	require.NoError(t, err)

	dataCV := encData.FindElement("./CipherData/CipherValue")
	require.NotNil(t, dataCV)
	raw, err := base64.StdEncoding.DecodeString(stripWhitespace(dataCV.Text()))
	require.NoError(t, err)
	block, err := aes.NewCipher(symKey)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	ns := gcm.NonceSize()
	require.Greater(t, len(raw), ns)
	plain, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	require.NoError(t, err)
	return plain
}

func stripWhitespace(s string) string {
	return strings.NewReplacer("\n", "", "\r", "", " ", "", "\t", "").Replace(s)
}

// E5: the decrypted assertion validates against the assertion XSD. Guards the
// A-2 fix (xmlns:xs declared inside the ciphertext).
func TestSAMLXMLVerify_E5_DecryptedAssertionValidatesAgainstXSD(t *testing.T) {
	requireXMLTool(t, "xmllint", "libxml2-utils", "XSD validation of the decrypted assertion")
	env := setupOIDCE2EEnvWithClock(t, e2eFixedClock)
	spKey, spCertPEM := generateSPKeyPair(t)

	require.NoError(t, env.db.Create(&models.SAMLClientGORM{
		ID: "e2e-e5", TenantID: "tenant-a", Name: "e2e-e5", EntityID: "http://sp.example.test/e5",
		ACSURL: "http://sp.example.test/acs", SPEncryptionCertificate: spCertPEM,
		AllowedScopes: []string{"openid", "profile"}, Active: true,
	}).Error)
	require.NoError(t, env.db.Model(&models.SAMLClientGORM{}).Where("id = ?", "e2e-e5").
		Updates(map[string]interface{}{"sign_response": true, "sign_assertion": true, "encrypt_assertion": true}).Error)

	ch := startE2EIdPSSO(t, env, buildAuthnRequestXML("http://sp.example.test/e5", "http://sp.example.test/acs", ""))
	root := parseE2ESAMLResponse(t, followE2ERedirect(t, env, acceptE2ESAMLLogin(t, env, ch)))

	enc := samlxml.DirectChild(root, "urn:oasis:names:tc:SAML:2.0:assertion", "EncryptedAssertion")
	require.NotNil(t, enc, "response must carry an EncryptedAssertion")
	require.Nil(t, samlxml.DirectChild(root, "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion"), "no plaintext Assertion")

	plain := decryptEncryptedAssertion(t, enc, spKey)
	// Sanity: the recovered assertion declares xs so the QName resolves.
	require.Contains(t, string(plain), `xmlns:xs="`+xmlSchemaNS+`"`, "decrypted assertion must declare xmlns:xs")
	file := writeTemp(t, "decrypted_assertion.xml", plain)

	code, out := runCmd("xmllint", "--nonet", "--noout", "--schema", assertionXSD, file)
	require.Equalf(t, 0, code, "decrypted assertion must validate against the SAML assertion XSD; xmllint output:\n%s", out)
}
