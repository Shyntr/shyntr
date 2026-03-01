package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	crewjamsaml "github.com/crewjam/saml"
	"github.com/google/uuid"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/core/auth"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/internal/data/repository"
	goxmldsig "github.com/russellhaering/goxmldsig"
)

type SingleCertStore struct {
	Cert *x509.Certificate
}

type PersistentAssertionMaker struct {
	crewjamsaml.DefaultAssertionMaker
}

func (s *SingleCertStore) Certificates() ([]*x509.Certificate, error) {
	return []*x509.Certificate{s.Cert}, nil
}

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
		EntityID:          baseURLStr,
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
		if !conn.SignRequest {
			sp.Key = nil
			sp.SignatureMethod = ""
		}
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
		binding = saml.HTTPPostBinding
		ssoURL = sp.GetSSOBindingLocation(binding)
	}

	if ssoURL == "" {
		return "", "", fmt.Errorf("no SSO URL found for HTTP-Redirect or HTTP-POST bindings")
	}

	req, err := sp.MakeAuthenticationRequest(ssoURL, binding, relayState)
	if err != nil {
		return "", "", fmt.Errorf("failed to create auth request: %w", err)
	}

	if binding == saml.HTTPRedirectBinding {
		redirectURL, err := req.Redirect(relayState, sp)
		if err != nil {
			return "", "", fmt.Errorf("failed to generate redirect url: %w", err)
		}
		return redirectURL.String(), req.ID, nil
	}

	return string(req.Post(relayState)), req.ID, nil
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

	if err := s.Repo.CheckAndSaveMessageID(ctx, assertion.ID, tenantID, 1*time.Hour); err != nil {
		return nil, "", fmt.Errorf("security alert (replay detected): %w", err)
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
		AssertionMaker:          &PersistentAssertionMaker{},
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
			spMetadata.SPSSODescriptors[0].KeyDescriptors = append(spMetadata.SPSSODescriptors[0].KeyDescriptors, keyDescriptor)

			signingKey := keyDescriptor
			signingKey.Use = "signing"
			spMetadata.SPSSODescriptors[0].KeyDescriptors = append(spMetadata.SPSSODescriptors[0].KeyDescriptors, signingKey)
		}
	}

	return spMetadata, nil
}

func (s *Service) ParseAuthnRequest(ctx context.Context, tenantID string, req *http.Request) (*saml.AuthnRequest, error) {
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

	var xmlBytes []byte
	if isRedirectBinding {
		flater := flate.NewReader(bytes.NewReader(decoded))
		inflated, err := io.ReadAll(flater)
		flater.Close()
		if err == nil {
			xmlBytes = inflated
		} else {
			xmlBytes = decoded
		}
	} else {
		xmlBytes = decoded
	}

	var authReq saml.AuthnRequest
	if err := xml.Unmarshal(xmlBytes, &authReq); err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth request: %w", err)
	}

	if err := s.Repo.CheckAndSaveMessageID(ctx, authReq.ID, tenantID, 15*time.Minute); err != nil {
		return nil, fmt.Errorf("security alert (replay detected): %w", err)
	}

	issuer := authReq.Issuer.Value
	if issuer == "" {
		return nil, fmt.Errorf("missing issuer in AuthnRequest")
	}

	var spClient models.SAMLClient
	if err := s.Repo.DB.Where("entity_id = ? AND tenant_id = ?", issuer, tenantID).First(&spClient).Error; err != nil {
		return nil, fmt.Errorf("unknown service provider: %s", issuer)
	}

	if spClient.SPCertificate == "" {
		return nil, fmt.Errorf("service provider signature validation failed: no certificate registered for entity %s", issuer)
	}

	block, _ := pem.Decode([]byte(spClient.SPCertificate))
	if block == nil {
		return nil, fmt.Errorf("invalid SP certificate format")
	}
	spCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SP certificate: %w", err)
	}

	if isRedirectBinding {
		if err := verifyRedirectSignature(req, spCert); err != nil {
			return nil, fmt.Errorf("signature validation failed: %w", err)
		}
	} else {
		if err := verifyPostSignature(xmlBytes, spCert); err != nil {
			return nil, fmt.Errorf("xml signature validation failed: %w", err)
		}
	}

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

	nameIDFormat := string(saml.PersistentNameIDFormat)
	if authReq.NameIDPolicy != nil && authReq.NameIDPolicy.Format != nil {
		requestedFormat := *authReq.NameIDPolicy.Format
		if requestedFormat != "" {
			nameIDFormat = requestedFormat
		}
	}

	var samlStatus saml.Status
	var assertion *saml.Assertion
	nameIDValue := subject

	switch nameIDFormat {
	case string(saml.EmailAddressNameIDFormat):
		email, ok := userAttributes["email"].(string)
		if !ok || email == "" {
			samlStatus = saml.Status{
				StatusCode: saml.StatusCode{
					Value: saml.StatusRequester,
					StatusCode: &saml.StatusCode{
						Value: "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy",
					},
				},
				StatusMessage: &saml.StatusMessage{
					Value: "Required email address is missing for the user",
				},
			}
		} else {
			nameIDValue = email
		}

	case string(saml.TransientNameIDFormat):
		nameIDValue = uuid.New().String()
	}

	if samlStatus.StatusCode.Value == "" {
		samlStatus = saml.Status{
			StatusCode: saml.StatusCode{
				Value: saml.StatusSuccess,
			},
		}

		authnContextClass := "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" // Varsayılan: Şifre
		if amrList, ok := userAttributes["amr"].([]interface{}); ok {
			for _, m := range amrList {
				if m == "ext" || m == "mfa" {
					// Dış sağlayıcı (Federated) veya MFA ile girildiyse
					authnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession"
				}
			}
		}

		assertion = &saml.Assertion{
			ID:           fmt.Sprintf("id-%d", now.UnixNano()),
			IssueInstant: now,
			Version:      "2.0",
			Issuer: saml.Issuer{
				Value: idp.MetadataURL.String(),
			},
			Subject: &saml.Subject{
				NameID: &saml.NameID{
					Format: nameIDFormat,
					Value:  nameIDValue,
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
					SessionIndex: fmt.Sprintf("id-%d", now.UnixNano()),
					AuthnContext: saml.AuthnContext{
						AuthnContextClassRef: &saml.AuthnContextClassRef{
							Value: authnContextClass,
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

		for k, v := range userAttributes {
			var attrValues []saml.AttributeValue

			switch val := v.(type) {
			case []string:
				for _, item := range val {
					attrValues = append(attrValues, saml.AttributeValue{
						Type:  "xs:string",
						Value: item,
					})
				}
			case []interface{}:
				for _, item := range val {
					attrValues = append(attrValues, saml.AttributeValue{
						Type:  "xs:string",
						Value: fmt.Sprintf("%v", item),
					})
				}
			default:
				attrValues = append(attrValues, saml.AttributeValue{
					Type:  "xs:string",
					Value: fmt.Sprintf("%v", val),
				})
			}

			assertion.AttributeStatements[0].Attributes = append(assertion.AttributeStatements[0].Attributes, saml.Attribute{
				Name:       k,
				NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
				Values:     attrValues,
			})
		}
	}

	var finalAssertionElement *etree.Element

	if assertion != nil {
		assertBytes, err := xml.Marshal(assertion)
		if err != nil {
			return "", err
		}
		docAssert := etree.NewDocument()
		if err := docAssert.ReadFromBytes(assertBytes); err != nil {
			return "", fmt.Errorf("failed to parse assertion xml: %w", err)
		}
		rootAssert := docAssert.Root()

		if sp.SignAssertion {
			signedAssertBytes, err := s.signElementXML(assertBytes, idp.Key.(*rsa.PrivateKey), idp.Certificate)
			if err != nil {
				return "", fmt.Errorf("failed to sign assertion: %w", err)
			}
			docAssert = etree.NewDocument()
			docAssert.ReadFromBytes(signedAssertBytes)
			rootAssert = docAssert.Root()
		}

		finalAssertionElement = rootAssert

		if sp.EncryptAssertion && sp.SPCertificate != "" {
			block, _ := pem.Decode([]byte(sp.SPCertificate))
			if block != nil {
				spCert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					assertBytesToEncrypt, _ := docAssert.WriteToBytes()
					encryptedElem, err := encryptAssertionBytes(assertBytesToEncrypt, spCert)
					if err != nil {
						return "", fmt.Errorf("failed to encrypt assertion: %w", err)
					}
					finalAssertionElement = encryptedElem
				}
			}
		}
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
		Status: samlStatus,
	}

	respBytes, err := xml.Marshal(response)
	if err != nil {
		return "", err
	}

	docResp := etree.NewDocument()
	if err := docResp.ReadFromBytes(respBytes); err != nil {
		return "", fmt.Errorf("failed to parse response xml: %w", err)
	}
	rootResp := docResp.Root()

	if finalAssertionElement != nil {
		rootResp.AddChild(finalAssertionElement)
	}

	finalXMLBytes, err := docResp.WriteToBytes()
	if err != nil {
		return "", err
	}

	if sp.SignResponse {
		finalXMLBytes, err = s.signElementXML(finalXMLBytes, idp.Key.(*rsa.PrivateKey), idp.Certificate)
		if err != nil {
			return "", fmt.Errorf("failed to sign response: %w", err)
		}
	}

	b64Resp := base64.StdEncoding.EncodeToString(finalXMLBytes)
	return buildHTMLForm(authReq.AssertionConsumerServiceURL, b64Resp, relayState), nil
}

func buildHTMLForm(acsURL, b64Resp, relayState string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><body onload="document.forms[0].submit()"><form method="post" action="%s"><input type="hidden" name="SAMLResponse" value="%s" /><input type="hidden" name="RelayState" value="%s" /><noscript><input type="submit" value="Continue" /></noscript></form></body></html>`,
		html.EscapeString(acsURL),
		b64Resp,
		html.EscapeString(relayState))
}

func encryptAssertionBytes(assertionXML []byte, cert *x509.Certificate) (*etree.Element, error) {
	symKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, symKey); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(symKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	encryptedData := gcm.Seal(nonce, nonce, assertionXML, nil)
	encryptedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, cert.PublicKey.(*rsa.PublicKey), symKey, nil)
	if err != nil {
		return nil, err
	}

	encAssert := etree.NewElement("saml:EncryptedAssertion")
	encAssert.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")

	encData := encAssert.CreateElement("xenc:EncryptedData")
	encData.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	encData.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")

	encMethod := encData.CreateElement("xenc:EncryptionMethod")
	encMethod.CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#aes256-gcm")

	keyInfo := encData.CreateElement("ds:KeyInfo")
	keyInfo.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")

	encKey := keyInfo.CreateElement("xenc:EncryptedKey")
	encKeyMethod := encKey.CreateElement("xenc:EncryptionMethod")
	encKeyMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p")

	encKeyCipher := encKey.CreateElement("xenc:CipherData")
	encKeyVal := encKeyCipher.CreateElement("xenc:CipherValue")
	encKeyVal.SetText(base64.StdEncoding.EncodeToString(encryptedKey))

	cipherData := encData.CreateElement("xenc:CipherData")
	cipherVal := cipherData.CreateElement("xenc:CipherValue")
	cipherVal.SetText(base64.StdEncoding.EncodeToString(encryptedData))

	return encAssert, nil
}

func (s *Service) signElementXML(xmlBytes []byte, key *rsa.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	signingContext, err := goxmldsig.NewSigningContext(key, [][]byte{cert.Raw})
	if err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, err
	}
	root := doc.Root()

	if root.SelectAttr("ID") == nil {
		return nil, errors.New("cannot sign element without ID attribute")
	}

	signedElement, err := signingContext.SignEnveloped(root)
	if err != nil {
		return nil, err
	}

	newDoc := etree.NewDocument()
	newDoc.SetRoot(signedElement)
	return newDoc.WriteToBytes()
}

func verifyRedirectSignature(req *http.Request, cert *x509.Certificate) error {
	query := req.URL.Query()
	signature := query.Get("Signature")
	sigAlg := query.Get("SigAlg")
	samlRequest := query.Get("SAMLRequest")
	relayState := query.Get("RelayState")
	if signature == "" {
		return errors.New("missing signature")
	}

	var signedString string
	if relayState != "" {
		signedString = fmt.Sprintf("SAMLRequest=%s&RelayState=%s&SigAlg=%s", url.QueryEscape(samlRequest), url.QueryEscape(relayState), url.QueryEscape(sigAlg))
	} else {
		signedString = fmt.Sprintf("SAMLRequest=%s&SigAlg=%s", url.QueryEscape(samlRequest), url.QueryEscape(sigAlg))
	}

	var hashAlg crypto.Hash
	switch sigAlg {
	case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
		hashAlg = crypto.SHA1
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
		hashAlg = crypto.SHA256
	default:
		return fmt.Errorf("unsupported signature algorithm: %s", sigAlg)
	}

	sigBytes, _ := base64.StdEncoding.DecodeString(signature)
	hasher := hashAlg.New()
	hasher.Write([]byte(signedString))
	return rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), hashAlg, hasher.Sum(nil), sigBytes)
}

func verifyPostSignature(xmlBytes []byte, cert *x509.Certificate) error {
	ks := &SingleCertStore{Cert: cert}
	ctx := goxmldsig.NewDefaultValidationContext(ks)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return err
	}
	if doc.Root() == nil {
		return errors.New("empty xml doc")
	}
	_, err := ctx.Validate(doc.Root())
	return err
}

func (s *Service) RegisterConnection(ctx context.Context, tenantID, name, metadataXML string) (*models.SAMLConnection, error) {
	meta := &saml.EntityDescriptor{}
	if err := xml.Unmarshal([]byte(metadataXML), meta); err != nil {
		return nil, err
	}
	conn := &models.SAMLConnection{
		TenantID: tenantID, Name: name, IdpMetadataXML: metadataXML, IdpEntityID: meta.EntityID, Active: true,
	}
	return conn, s.Repo.CreateConnection(ctx, conn)
}

func (m *PersistentAssertionMaker) MakeAssertion(req *crewjamsaml.IdpAuthnRequest, session *crewjamsaml.Session) error {
	err := m.DefaultAssertionMaker.MakeAssertion(req, session)
	if err != nil {
		return err
	}

	if req.Assertion != nil && req.Assertion.Subject != nil && req.Assertion.Subject.NameID != nil {
		req.Assertion.Subject.NameID.Format = string(crewjamsaml.PersistentNameIDFormat)
	}

	return nil
}

func (s *Service) generateSelfSignedCert(key *rsa.PrivateKey) (*x509.Certificate, error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Shyntr SAML IdP"},
		NotBefore: time.Now().Add(-1 * time.Minute), NotAfter: time.Now().Add(365 * 24 * time.Hour * 10),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}
