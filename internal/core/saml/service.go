package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/core/auth"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/internal/data/repository"
	goxmldsig "github.com/russellhaering/goxmldsig"
)

type Service struct {
	Repo   *repository.SAMLRepository
	KeyMgr *auth.KeyManager
	Config *config.Config
}

func NewService(repo *repository.SAMLRepository, km *auth.KeyManager, cfg *config.Config) *Service {
	return &Service{
		Repo:   repo,
		KeyMgr: km,
		Config: cfg,
	}
}

func (s *Service) BuildServiceProvider(ctx context.Context, tenantID string, conn *models.SAMLConnection) (*saml.ServiceProvider, error) {
	baseURLStr := fmt.Sprintf("%s/t/%s/saml", s.Config.BaseIssuerURL, tenantID)

	metadataURL, _ := url.Parse(baseURLStr + "/sp/metadata")
	acsURL, _ := url.Parse(baseURLStr + "/sp/acs")
	sloURL, _ := url.Parse(baseURLStr + "/sp/slo")

	var privKey *rsa.PrivateKey
	var cert *x509.Certificate
	var err error

	if conn != nil && conn.SPPrivateKey != "" {
		block, _ := pem.Decode([]byte(conn.SPPrivateKey))
		if block == nil {
			return nil, errors.New("failed to decode connection private key PEM")
		}
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse connection private key: %w", err)
		}
		if conn.SPCertificate == "" {
			cert, err = s.generateSelfSignedCert(privKey)
		} else {
			block, _ := pem.Decode([]byte(conn.SPCertificate))
			if block == nil {
				return nil, errors.New("failed to decode connection cert PEM")
			}
			cert, err = x509.ParseCertificate(block.Bytes)
		}
	} else {
		privKey = s.KeyMgr.GetActivePrivateKey()
		cert, err = s.generateSelfSignedCert(privKey)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to prepare certs: %w", err)
	}

	sp := &saml.ServiceProvider{
		EntityID:          metadataURL.String(),
		Key:               privKey,
		Certificate:       cert,
		MetadataURL:       *metadataURL,
		AcsURL:            *acsURL,
		SloURL:            *sloURL,
		IDPMetadata:       &saml.EntityDescriptor{},
		AllowIDPInitiated: true,
		SignatureMethod:   "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	}

	if conn != nil {
		sp.ForceAuthn = &conn.ForceAuthn
	}

	return sp, nil
}

func (s *Service) InitiateSSO(ctx context.Context, tenantID, connectionID, relayState string) (string, string, error) {
	conn, err := s.Repo.GetConnection(ctx, connectionID)
	if err != nil {
		return "", "", fmt.Errorf("connection not found: %w", err)
	}

	sp, err := s.BuildServiceProvider(ctx, tenantID, conn)
	if err != nil {
		return "", "", err
	}

	idpMetadata := &saml.EntityDescriptor{}
	if err := xml.Unmarshal([]byte(conn.IdpMetadataXML), idpMetadata); err != nil {
		return "", "", fmt.Errorf("invalid idp metadata xml: %w", err)
	}
	sp.IDPMetadata = idpMetadata

	binding := saml.HTTPRedirectBinding
	ssoURL := sp.GetSSOBindingLocation(binding)
	if ssoURL == "" {
		return "", "", fmt.Errorf("no SSO URL found for binding %s", binding)
	}

	req, err := sp.MakeAuthenticationRequest(ssoURL, binding, relayState)
	if err != nil {
		return "", "", fmt.Errorf("failed to create auth request: %w", err)
	}

	redirectURL, err := req.Redirect(relayState, sp)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate redirect url: %w", err)
	}

	return redirectURL.String(), req.ID, nil
}

func (s *Service) HandleACS(ctx context.Context, tenantID string, req *http.Request, possibleRequestID string) (*saml.Assertion, string, error) {
	sp, err := s.BuildServiceProvider(ctx, tenantID, nil)
	if err != nil {
		return nil, "", err
	}

	encodedResponse := req.FormValue("SAMLResponse")
	if encodedResponse == "" {
		return nil, "", fmt.Errorf("missing SAMLResponse")
	}

	decodedResponse, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		return nil, "", fmt.Errorf("invalid base64: %w", err)
	}

	var tempResponse struct {
		Issuer struct {
			Value string `xml:",chardata"`
		} `xml:"Issuer"`
	}
	if err := xml.Unmarshal(decodedResponse, &tempResponse); err != nil {
		return nil, "", fmt.Errorf("failed to parse XML for issuer: %w", err)
	}

	issuer := tempResponse.Issuer.Value
	if issuer == "" {
		return nil, "", fmt.Errorf("issuer not found in SAMLResponse")
	}

	conn, err := s.Repo.FindConnectionByEntityID(ctx, tenantID, issuer)
	if err != nil {
		return nil, "", fmt.Errorf("unknown idp issuer '%s': %w", issuer, err)
	}

	idpMetadata := &saml.EntityDescriptor{}
	if err := xml.Unmarshal([]byte(conn.IdpMetadataXML), idpMetadata); err != nil {
		return nil, "", fmt.Errorf("invalid stored metadata: %w", err)
	}
	sp.IDPMetadata = idpMetadata

	knownIDs := []string{}
	if possibleRequestID != "" {
		knownIDs = append(knownIDs, possibleRequestID)
	}

	assertion, err := sp.ParseResponse(req, knownIDs)
	if err != nil {
		return nil, "", fmt.Errorf("validation failed: %w", err)
	}

	relayState := req.FormValue("RelayState")
	return assertion, relayState, nil
}

func (s *Service) GetIdentityProvider(ctx context.Context, tenantID string) (*saml.IdentityProvider, error) {
	baseURLStr := fmt.Sprintf("%s/t/%s/saml", s.Config.BaseIssuerURL, tenantID)

	metadataURL, _ := url.Parse(baseURLStr + "/idp/metadata")
	ssoURL, _ := url.Parse(baseURLStr + "/idp/sso")

	privKey := s.KeyMgr.GetActivePrivateKey()
	cert, err := s.generateSelfSignedCert(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate idp cert: %w", err)
	}

	idp := &saml.IdentityProvider{
		Key:                     privKey,
		Certificate:             cert,
		MetadataURL:             *metadataURL,
		SSOURL:                  *ssoURL,
		SignatureMethod:         "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		ServiceProviderProvider: s,
	}

	return idp, nil
}

func (s *Service) GetServiceProvider(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	var samlClient models.SAMLClient
	if err := s.Repo.DB.Where("entity_id = ?", serviceProviderID).First(&samlClient).Error; err != nil {
		return nil, fmt.Errorf("service provider not found: %s", serviceProviderID)
	}

	spMetadata := &saml.EntityDescriptor{
		EntityID: serviceProviderID,
		SPSSODescriptors: []saml.SPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors:             []saml.KeyDescriptor{},
					},
				},
				AssertionConsumerServices: []saml.IndexedEndpoint{
					{
						Binding:  saml.HTTPPostBinding,
						Location: samlClient.ACSURL,
						Index:    1,
					},
				},
			},
		},
	}

	if samlClient.SPCertificate != "" {
		block, _ := pem.Decode([]byte(samlClient.SPCertificate))
		if block != nil {
			certStr := base64.StdEncoding.EncodeToString(block.Bytes)
			keyDescriptor := saml.KeyDescriptor{
				Use: "encryption",
				KeyInfo: saml.KeyInfo{
					X509Data: saml.X509Data{
						X509Certificates: []saml.X509Certificate{
							{Data: certStr},
						},
					},
				},
			}
			signingKeyDescriptor := keyDescriptor
			signingKeyDescriptor.Use = "signing"

			spMetadata.SPSSODescriptors[0].KeyDescriptors = append(spMetadata.SPSSODescriptors[0].KeyDescriptors, keyDescriptor, signingKeyDescriptor)
		}
	}

	return spMetadata, nil
}

func (s *Service) ParseAuthnRequest(ctx context.Context, tenantID string, req *http.Request) (*saml.AuthnRequest, error) {
	var rawRequest []byte
	var err error

	encodedReq := req.URL.Query().Get("SAMLRequest")
	isRedirectBinding := encodedReq != ""

	if encodedReq == "" {
		encodedReq = req.FormValue("SAMLRequest")
		if encodedReq == "" {
			return nil, fmt.Errorf("missing SAMLRequest parameter")
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(encodedReq)
	if err != nil {
		if unescaped, err := url.QueryUnescape(encodedReq); err == nil {
			if decoded2, err := base64.StdEncoding.DecodeString(unescaped); err == nil {
				decoded = decoded2
			} else {
				return nil, fmt.Errorf("failed to base64 decode: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to base64 decode: %w", err)
		}
	}

	if isRedirectBinding {
		flater := flate.NewReader(bytes.NewReader(decoded))
		inflated, err := io.ReadAll(flater)
		flater.Close()
		if err == nil {
			rawRequest = inflated
		} else {
			rawRequest = decoded
		}
	} else {
		rawRequest = decoded
	}

	var authReq saml.AuthnRequest
	if err := xml.Unmarshal(rawRequest, &authReq); err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth request: %w", err)
	}

	// TODO: Signature Validation (Advanced)
	// Redirect binding için imza query string'deki SigAlg ve Signature ile doğrulanır.
	// POST binding için XML içinde <ds:Signature> vardır.
	// Şu anlık protokol uyumluluğu (Schema check) yapıyoruz.

	return &authReq, nil
}

func (s *Service) GenerateSAMLResponse(ctx context.Context, tenantID string, authReq *saml.AuthnRequest, sp *models.SAMLClient, userAttributes map[string]interface{}, relayState string) (string, error) {
	idp, err := s.GetIdentityProvider(ctx, tenantID)
	if err != nil {
		return "", err
	}

	now := time.Now()
	subject := "unknown"
	if v, ok := userAttributes["sub"].(string); ok {
		subject = v
	} else if v, ok := userAttributes["email"].(string); ok {
		subject = v
	}

	samlAttributes := make(map[string][]string)
	for k, v := range userAttributes {
		samlAttributes[k] = []string{fmt.Sprintf("%v", v)}
	}

	assertionID := fmt.Sprintf("id-%d", now.UnixNano())

	assertion := saml.Assertion{
		ID:           assertionID,
		IssueInstant: now,
		Version:      "2.0",
		Issuer: saml.Issuer{
			Value: idp.MetadataURL.String(),
		},
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Format: string(saml.EmailAddressNameIDFormat),
				Value:  subject,
			},
			SubjectConfirmations: []saml.SubjectConfirmation{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &saml.SubjectConfirmationData{
						InResponseTo: authReq.ID,
						NotOnOrAfter: now.Add(5 * time.Minute),
						Recipient:    authReq.AssertionConsumerServiceURL,
					},
				},
			},
		},
		Conditions: &saml.Conditions{
			NotBefore:    now.Add(-5 * time.Minute),
			NotOnOrAfter: now.Add(5 * time.Minute),
			AudienceRestrictions: []saml.AudienceRestriction{
				{
					Audience: saml.Audience{Value: authReq.Issuer.Value},
				},
			},
		},
		AuthnStatements: []saml.AuthnStatement{
			{
				AuthnInstant: now,
				SessionIndex: assertionID,
				AuthnContext: saml.AuthnContext{
					AuthnContextClassRef: &saml.AuthnContextClassRef{
						Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
					},
				},
			},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: []saml.Attribute{},
			},
		},
	}

	for k, vals := range samlAttributes {
		attr := saml.Attribute{
			Name:       k,
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		}
		for _, v := range vals {
			attr.Values = append(attr.Values, saml.AttributeValue{
				Type:  "xs:string",
				Value: v,
			})
		}
		assertion.AttributeStatements[0].Attributes = append(assertion.AttributeStatements[0].Attributes, attr)
	}

	response := &saml.Response{
		ID:           fmt.Sprintf("resp-%d", now.UnixNano()),
		InResponseTo: authReq.ID,
		IssueInstant: now,
		Version:      "2.0",
		Destination:  authReq.AssertionConsumerServiceURL,
		Issuer: &saml.Issuer{
			Value: idp.MetadataURL.String(),
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{
				Value: saml.StatusSuccess,
			},
		},
		Assertion: &assertion,
	}

	respBytes, err := xml.Marshal(response)
	if err != nil {
		return "", fmt.Errorf("failed to marshal response: %w", err)
	}

	signedXML, err := s.signResponseXML(respBytes, idp.Key.(*rsa.PrivateKey), idp.Certificate)
	if err != nil {
		return "", fmt.Errorf("failed to sign response: %w", err)
	}

	b64Resp := base64.StdEncoding.EncodeToString(signedXML)

	htmlForm := fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
		<body onload="document.forms[0].submit()">
			<form method="post" action="%s">
				<input type="hidden" name="SAMLResponse" value="%s" />
				<input type="hidden" name="RelayState" value="%s" />
				<noscript>
					<p>Please click the button below to continue.</p>
					<input type="submit" value="Continue" />
				</noscript>
			</form>
		</body>
		</html>
	`, authReq.AssertionConsumerServiceURL, b64Resp, relayState)

	return htmlForm, nil
}

func (s *Service) signResponseXML(xmlBytes []byte, key *rsa.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	signingContext, _ := goxmldsig.NewSigningContext(key, [][]byte{cert.Raw})

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, err
	}

	root := doc.Root()
	if root == nil {
		return nil, errors.New("empty xml doc")
	}

	signedElement, err := signingContext.SignEnveloped(root)
	if err != nil {
		return nil, err
	}

	newDoc := etree.NewDocument()
	newDoc.SetRoot(signedElement)

	return newDoc.WriteToBytes()
}

func (s *Service) RegisterConnection(ctx context.Context, tenantID, name, metadataXML string) (*models.SAMLConnection, error) {
	meta := &saml.EntityDescriptor{}
	if err := xml.Unmarshal([]byte(metadataXML), meta); err != nil {
		return nil, fmt.Errorf("invalid metadata xml: %w", err)
	}
	conn := &models.SAMLConnection{
		TenantID:       tenantID,
		Name:           name,
		IdpMetadataXML: metadataXML,
		IdpEntityID:    meta.EntityID,
		Active:         true,
	}
	err := s.Repo.CreateConnection(ctx, conn)
	return conn, err
}

func (s *Service) generateSelfSignedCert(key *rsa.PrivateKey) (*x509.Certificate, error) {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Shyntr SAML Service Provider"},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour * 10),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}
