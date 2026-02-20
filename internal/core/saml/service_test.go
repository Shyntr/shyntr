package saml_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/glebarez/sqlite"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/core/auth"
	"github.com/nevzatcirak/shyntr/internal/core/saml"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/internal/data/repository"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupSAMLService(t *testing.T) (*saml.Service, *gorm.DB) {
	logger.InitLogger("info")

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}

	err = db.AutoMigrate(
		&models.SAMLClient{},
		&models.SAMLConnection{},
		&models.SAMLReplayCache{},
		&models.SigningKey{},
	)
	if err != nil {
		t.Fatalf("failed to migrate database: %v", err)
	}

	cfg := &config.Config{
		AppSecret:     "12345678901234567890123456789012",
		BaseIssuerURL: "http://localhost:8080",
	}

	km := auth.NewKeyManager(db, cfg)
	_ = km.GetActivePrivateKey()

	repo := repository.NewSAMLRepository(db)

	return saml.NewService(repo, km, cfg), db
}

func TestSAMLService_Security_ParseAuthnRequest(t *testing.T) {
	svc, db := setupSAMLService(t)
	ctx := context.Background()
	tenantID := "default"

	defer db.Exec("DELETE FROM saml_clients")
	defer db.Exec("DELETE FROM saml_replay_caches")

	t.Run("Missing SAMLRequest Parameter", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://localhost/saml/sso", nil)
		_, err := svc.ParseAuthnRequest(ctx, tenantID, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing SAMLRequest parameter")
	})

	t.Run("Invalid Base64 Encoding", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://localhost/saml/sso?SAMLRequest=Invalid!@#Base64", nil)
		_, err := svc.ParseAuthnRequest(ctx, tenantID, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to base64 decode")
	})

	t.Run("Unknown Service Provider", func(t *testing.T) {
		dummyXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="12345"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">unknown-hacker-sp</saml:Issuer></samlp:AuthnRequest>`
		encodedXML := base64.StdEncoding.EncodeToString([]byte(dummyXML))
		escapedXML := url.QueryEscape(encodedXML)

		req, _ := http.NewRequest("GET", "http://localhost/saml/sso?SAMLRequest="+escapedXML, nil)
		_, err := svc.ParseAuthnRequest(ctx, tenantID, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown service provider: unknown-hacker-sp")
	})

	t.Run("Missing SP Certificate", func(t *testing.T) {
		db.Create(&models.SAMLClient{
			EntityID:      "known-sp-no-cert",
			TenantID:      tenantID,
			Name:          "Test SP",
			SPCertificate: "",
		})

		dummyXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="123456"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">known-sp-no-cert</saml:Issuer></samlp:AuthnRequest>`
		encodedXML := base64.StdEncoding.EncodeToString([]byte(dummyXML))
		escapedXML := url.QueryEscape(encodedXML)

		req, _ := http.NewRequest("GET", "http://localhost/saml/sso?SAMLRequest="+escapedXML, nil)
		_, err := svc.ParseAuthnRequest(ctx, tenantID, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no certificate registered for entity known-sp-no-cert")
	})
}

func TestSAMLService_GenerateSAMLResponse_AttributeMapping(t *testing.T) {
	svc, db := setupSAMLService(t)
	ctx := context.Background()
	tenantID := "default"

	spClient := &models.SAMLClient{
		EntityID:      "mock-sp",
		TenantID:      tenantID,
		ACSURL:        "https://sp.example.com/acs",
		SignAssertion: false,
		SignResponse:  false,
	}
	db.Create(spClient)

	authReq := &crewjamsaml.AuthnRequest{
		ID:                          "mock-auth-req-123",
		Issuer:                      &crewjamsaml.Issuer{Value: "mock-sp"},
		AssertionConsumerServiceURL: "https://sp.example.com/acs",
	}

	userAttrs := map[string]interface{}{
		"sub":        "user-test-uuid",
		"email":      "test@example.com",
		"department": "engineering",
		"role":       "admin",
	}

	htmlForm, err := svc.GenerateSAMLResponse(ctx, tenantID, authReq, spClient, userAttrs, "mock-relay-state")
	require.NoError(t, err)

	assert.Contains(t, htmlForm, `action="https://sp.example.com/acs"`)
	assert.Contains(t, htmlForm, `value="mock-relay-state"`)

	re := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)
	matches := re.FindStringSubmatch(htmlForm)
	require.Len(t, matches, 2)

	xmlBytes, err := base64.StdEncoding.DecodeString(matches[1])
	require.NoError(t, err)
	xmlStr := string(xmlBytes)

	assert.Contains(t, xmlStr, `InResponseTo="mock-auth-req-123"`)
	assert.Contains(t, xmlStr, `>user-test-uuid<`)
	assert.Contains(t, xmlStr, `Name="email"`)
	assert.Contains(t, xmlStr, `>test@example.com<`)
	assert.Contains(t, xmlStr, `Name="department"`)
	assert.Contains(t, xmlStr, `>engineering<`)
	assert.Contains(t, xmlStr, `Name="role"`)
	assert.Contains(t, xmlStr, `>admin<`)
}

func TestSAMLService_CryptoMatrix(t *testing.T) {
	svc, db := setupSAMLService(t)
	ctx := context.Background()
	tenantID := "default"

	t.Run("SP Outbound: SignRequest Matrix", func(t *testing.T) {
		dummyIdpMetadata := `<EntityDescriptor entityID="test-idp" xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`

		db.Create(&models.SAMLConnection{
			ID:             "conn-signed",
			TenantID:       tenantID,
			IdpEntityID:    "test-idp",
			IdpMetadataXML: dummyIdpMetadata,
			SignRequest:    true,
		})

		connUnsigned := models.SAMLConnection{
			ID:             "conn-unsigned",
			TenantID:       tenantID,
			IdpEntityID:    "test-idp",
			IdpMetadataXML: dummyIdpMetadata,
		}
		db.Create(&connUnsigned)
		db.Model(&connUnsigned).Update("sign_request", false)

		signedURL, _, err := svc.InitiateSSO(ctx, tenantID, "conn-signed", "relay-1")
		require.NoError(t, err)
		parsedSignedURL, _ := url.Parse(signedURL)

		assert.NotEmpty(t, parsedSignedURL.Query().Get("Signature"), "Expected Signature parameter in URL when SignRequest is true")
		assert.NotEmpty(t, parsedSignedURL.Query().Get("SigAlg"), "Expected SigAlg parameter in URL when SignRequest is true")

		unsignedURL, _, err := svc.InitiateSSO(ctx, tenantID, "conn-unsigned", "relay-2")
		require.NoError(t, err)
		parsedUnsignedURL, _ := url.Parse(unsignedURL)

		assert.Empty(t, parsedUnsignedURL.Query().Get("Signature"), "Did not expect Signature parameter when SignRequest is false")
	})

	t.Run("IdP Outbound: Signature & Encryption Matrix", func(t *testing.T) {
		dummyIdp, _ := svc.GetIdentityProvider(ctx, tenantID)
		spCertStr := base64.StdEncoding.EncodeToString(dummyIdp.Certificate.Raw)
		spCertPEM := "-----BEGIN CERTIFICATE-----\n" + spCertStr + "\n-----END CERTIFICATE-----"

		authReq := &crewjamsaml.AuthnRequest{
			ID:                          "matrix-req-123",
			Issuer:                      &crewjamsaml.Issuer{Value: "matrix-sp"},
			AssertionConsumerServiceURL: "https://sp.example.com/acs",
		}
		userAttrs := map[string]interface{}{"sub": "user-123"}

		scenarios := []struct {
			name             string
			signResponse     bool
			signAssertion    bool
			encryptAssertion bool
		}{
			{"No Signature, No Encryption", false, false, false},
			{"Sign Response Only", true, false, false},
			{"Sign Assertion Only", false, true, false},
			{"Sign Both Response and Assertion", true, true, false},
			{"Encrypt Assertion (No Signatures)", false, false, true},
			{"Full Security (Sign Both + Encrypt)", true, true, true},
		}

		for _, s := range scenarios {
			t.Run(s.name, func(t *testing.T) {
				spClient := &models.SAMLClient{
					EntityID:         "matrix-sp",
					TenantID:         tenantID,
					ACSURL:           "https://sp.example.com/acs",
					SignResponse:     s.signResponse,
					SignAssertion:    s.signAssertion,
					EncryptAssertion: s.encryptAssertion,
					SPCertificate:    spCertPEM,
				}

				htmlForm, err := svc.GenerateSAMLResponse(ctx, tenantID, authReq, spClient, userAttrs, "relay")
				require.NoError(t, err)

				re := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)
				matches := re.FindStringSubmatch(htmlForm)
				require.Len(t, matches, 2)

				xmlBytes, err := base64.StdEncoding.DecodeString(matches[1])
				require.NoError(t, err)
				xmlStr := string(xmlBytes)

				if s.encryptAssertion {
					assert.Contains(t, xmlStr, "EncryptedAssertion", "Expected assertion to be encrypted")
					assert.Contains(t, xmlStr, "EncryptedData", "Expected xenc:EncryptedData block")
					assert.NotContains(t, xmlStr, `NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"`, "Plaintext attributes should NOT leak in encrypted assertion")
				} else {
					assert.Contains(t, xmlStr, "Assertion", "Expected plaintext assertion")
					assert.NotContains(t, xmlStr, "EncryptedAssertion", "Did not expect encryption")
				}
				sigCount := strings.Count(xmlStr, "SignatureValue") / 2

				expectedSigs := 0
				if s.signResponse {
					expectedSigs++
				}
				if s.signAssertion && !s.encryptAssertion {
					expectedSigs++
				}

				if !s.encryptAssertion {
					assert.Equal(t, expectedSigs, sigCount, "Mismatch in number of XML signatures")
				}
			})
		}
	})
}
