package usecase

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
	"strings"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/application/security"
	"github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/beevik/etree"
	crewjamsaml "github.com/crewjam/saml"
	"github.com/google/uuid"
	goxmldsig "github.com/russellhaering/goxmldsig"
)

type SamlBuilderUseCase interface {
	BuildServiceProvider(ctx context.Context, tenantID string, conn *model.SAMLConnection) (*crewjamsaml.ServiceProvider, error)
	InitiateSSO(ctx context.Context, tenantID, connectionID, loginChallenge, csrfToken string) (string, string, error)
	HandleACS(ctx context.Context, tenantID string, req *http.Request, possibleRequestID string) (*crewjamsaml.Assertion, string, error)
	GetIdentityProvider(ctx context.Context, tenantID string) (*crewjamsaml.IdentityProvider, error)
	GetServiceProvider(r *http.Request, serviceProviderID string) (*crewjamsaml.EntityDescriptor, error)
	ParseAuthnRequest(ctx context.Context, tenantID string, req *http.Request) (*crewjamsaml.AuthnRequest, error)
	VerifyInboundRedirectSignature(req *http.Request, certPEM string) error
	GenerateSAMLResponse(ctx context.Context, tenantID string, authReq *crewjamsaml.AuthnRequest, sp *model.SAMLClient, userAttributes map[string]interface{}, relayState string) (string, error)
	GenerateSAMLErrorResponse(ctx context.Context, tenantID string, authReq *crewjamsaml.AuthnRequest, sp *model.SAMLClient, topLevelStatus, statusMessage, relayState string) (string, error)
	RegisterConnection(ctx context.Context, tenantID, name, metadataXML string) (*model.SAMLConnection, error)
	ParseLogoutRequest(req *http.Request) (*crewjamsaml.LogoutRequest, error)
	GenerateLogoutResponse(ctx context.Context, tenantID string, req *crewjamsaml.LogoutRequest, sp *model.SAMLClient, relayState string) (string, error)
	signElementXML(xmlBytes []byte, key *rsa.PrivateKey, cert *x509.Certificate) ([]byte, error)
	generateSelfSignedCert(key *rsa.PrivateKey) (*x509.Certificate, error)
	VerifyRelayState(ctx context.Context, tenantID, encryptedState, csrfToken string) (*security.FederationStatePayload, error)
}

type samlBuilderUseCase struct {
	clientRepo    port.SAMLClientRepository
	connRepo      port.SAMLConnectionRepository
	replayRepo    port.SAMLReplayRepository
	KeyMgr        utils.KeyManager
	Config        *config.Config
	stateProvider security.FederationStateProvider
	clock         func() time.Time
}

func NewSamlBuilderUseCase(clientRepo port.SAMLClientRepository, connRepo port.SAMLConnectionRepository,
	replayRepo port.SAMLReplayRepository, km utils.KeyManager, cfg *config.Config, stateProvider security.FederationStateProvider) SamlBuilderUseCase {
	return NewSamlBuilderUseCaseWithClock(clientRepo, connRepo, replayRepo, km, cfg, stateProvider, nil)
}

// NewSamlBuilderUseCaseWithClock is like NewSamlBuilderUseCase but accepts an
// injectable clock so issuance timestamps are deterministic under test. A nil
// clock means wall-clock time (identical to NewSamlBuilderUseCase).
func NewSamlBuilderUseCaseWithClock(clientRepo port.SAMLClientRepository, connRepo port.SAMLConnectionRepository,
	replayRepo port.SAMLReplayRepository, km utils.KeyManager, cfg *config.Config, stateProvider security.FederationStateProvider,
	clock func() time.Time) SamlBuilderUseCase {
	return &samlBuilderUseCase{
		clientRepo:    clientRepo,
		connRepo:      connRepo,
		replayRepo:    replayRepo,
		KeyMgr:        km,
		Config:        cfg,
		stateProvider: stateProvider,
		clock:         clock,
	}
}

// now returns the current time from the injected clock, or wall-clock time when
// no clock is set. It tolerates a nil clock so a zero-value samlBuilderUseCase
// (as constructed directly in tests) does not panic.
func (s *samlBuilderUseCase) now() time.Time {
	if s.clock == nil {
		return time.Now()
	}
	return s.clock()
}

type SingleCertStore struct {
	Cert *x509.Certificate
}

type PersistentAssertionMaker interface {
	MakeAssertion(req *crewjamsaml.IdpAuthnRequest, session *crewjamsaml.Session)
}

type persistentAssertionMaker struct {
	crewjamsaml.DefaultAssertionMaker
}

func (s *SingleCertStore) Certificates() ([]*x509.Certificate, error) {
	return []*x509.Certificate{s.Cert}, nil
}
func (s *samlBuilderUseCase) BuildServiceProvider(ctx context.Context, tenantID string, conn *model.SAMLConnection) (*crewjamsaml.ServiceProvider, error) {
	baseURLStr := fmt.Sprintf("%s/t/%s/saml", s.Config.BaseIssuerURL, tenantID)

	metadataURL, _ := url.Parse(baseURLStr + "/sp/metadata")
	acsURL, _ := url.Parse(baseURLStr + "/sp/acs")
	sloURL, _ := url.Parse(baseURLStr + "/sp/slo")

	var privKey *rsa.PrivateKey
	var cert *x509.Certificate
	var err error

	if conn != nil && conn.SPPrivateKey != "" {
		block, _ := pem.Decode([]byte(conn.SPPrivateKey))
		privKey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
		if conn.SPCertificate != "" {
			certBlock, _ := pem.Decode([]byte(conn.SPCertificate))
			cert, _ = x509.ParseCertificate(certBlock.Bytes)
		} else {
			template := x509.Certificate{
				SerialNumber: big.NewInt(time.Now().Unix()), Subject: pkix.Name{CommonName: "Shyntr Custom SP"},
				NotBefore: time.Now().Add(-1 * time.Minute), NotAfter: time.Now().Add(365 * 24 * time.Hour * 10),
				KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			}
			certBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
			cert, _ = x509.ParseCertificate(certBytes)

			pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}))
			conn.SPCertificate = pemCert
			err := s.connRepo.Update(ctx, conn)
			if err != nil {
				return nil, err
			}
		}
	} else {
		privKey, cert, _, err = s.KeyMgr.GetActiveKeys(ctx, "sig")
		if err != nil {
			return nil, errors.New("failed to load active SAML crypto keys")
		}
	}

	if cert == nil || privKey == nil {
		return nil, errors.New("failed to load static SP keys")
	}

	sp := &crewjamsaml.ServiceProvider{
		EntityID:    baseURLStr,
		Key:         privKey,
		Certificate: cert,
		MetadataURL: *metadataURL,
		AcsURL:      *acsURL,
		SloURL:      *sloURL,
		LogoutBindings: []string{
			crewjamsaml.HTTPRedirectBinding,
			crewjamsaml.HTTPPostBinding,
		},
		IDPMetadata:       &crewjamsaml.EntityDescriptor{},
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

func (s *samlBuilderUseCase) InitiateSSO(ctx context.Context, tenantID, connectionID, loginChallenge, csrfToken string) (string, string, error) {
	conn, err := s.connRepo.GetByID(ctx, connectionID)
	if err != nil {
		return "", "", fmt.Errorf("connection not found: %w", err)
	}

	sp, err := s.BuildServiceProvider(ctx, tenantID, conn)
	if err != nil {
		return "", "", err
	}

	if conn.IdpMetadataXML != "" {
		idpMetadata := &crewjamsaml.EntityDescriptor{}
		if err := xml.Unmarshal([]byte(conn.IdpMetadataXML), idpMetadata); err == nil {
			sp.IDPMetadata = idpMetadata
		}
	} else if conn.IdpCertificate != "" {
		idpDescriptor := &crewjamsaml.EntityDescriptor{
			EntityID: conn.IdpEntityID,
			IDPSSODescriptors: []crewjamsaml.IDPSSODescriptor{
				{
					SingleSignOnServices: []crewjamsaml.Endpoint{
						{Binding: crewjamsaml.HTTPRedirectBinding, Location: conn.IdpSingleSignOn},
					},
				},
			},
		}

		if block, _ := pem.Decode([]byte(conn.IdpCertificate)); block != nil {
			idpDescriptor.IDPSSODescriptors[0].KeyDescriptors = append(
				idpDescriptor.IDPSSODescriptors[0].KeyDescriptors,
				crewjamsaml.KeyDescriptor{
					Use: "signing",
					KeyInfo: crewjamsaml.KeyInfo{
						X509Data: crewjamsaml.X509Data{X509Certificates: []crewjamsaml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(block.Bytes)}}},
					},
				},
			)
		}

		if block, _ := pem.Decode([]byte(conn.IdpEncryptionCertificate)); block != nil {
			idpDescriptor.IDPSSODescriptors[0].KeyDescriptors = append(
				idpDescriptor.IDPSSODescriptors[0].KeyDescriptors,
				crewjamsaml.KeyDescriptor{
					Use: "encryption",
					KeyInfo: crewjamsaml.KeyInfo{
						X509Data: crewjamsaml.X509Data{X509Certificates: []crewjamsaml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(block.Bytes)}}},
					},
				},
			)
		}

		sp.IDPMetadata = idpDescriptor
	}

	binding := crewjamsaml.HTTPRedirectBinding
	ssoURL := sp.GetSSOBindingLocation(binding)
	if ssoURL == "" {
		binding = crewjamsaml.HTTPPostBinding
		ssoURL = sp.GetSSOBindingLocation(binding)
	}

	if ssoURL == "" {
		return "", "", fmt.Errorf("no SSO URL found for HTTP-Redirect or HTTP-POST bindings")
	}

	relayState, err := s.stateProvider.Issue(ctx, security.IssueFederationStateInput{
		Action:         security.FederationActionSAMLLogin,
		TenantID:       tenantID,
		LoginChallenge: loginChallenge,
		ConnectionID:   connectionID,
		CSRFToken:      csrfToken,
		TTL:            10 * time.Minute,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to issue relay state: %w", err)
	}
	req, err := sp.MakeAuthenticationRequest(ssoURL, binding, crewjamsaml.HTTPPostBinding)
	if err != nil {
		return "", "", fmt.Errorf("failed to create auth request: %w", err)
	}

	if binding == crewjamsaml.HTTPRedirectBinding {
		redirectURL, err := req.Redirect(relayState, sp)
		if err != nil {
			return "", "", fmt.Errorf("failed to generate redirect url: %w", err)
		}
		return redirectURL.String(), req.ID, nil
	}

	return string(req.Post(relayState)), req.ID, nil
}

func (s *samlBuilderUseCase) HandleACS(ctx context.Context, tenantID string, req *http.Request, possibleRequestID string) (*crewjamsaml.Assertion, string, error) {
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

	conn, err := s.connRepo.GetConnectionByIdpEntity(ctx, tenantID, issuer)
	if err != nil {
		return nil, "", fmt.Errorf("unknown idp issuer '%s': %w", issuer, err)
	}

	if conn.IdpMetadataXML != "" {
		idpMetadata := &crewjamsaml.EntityDescriptor{}
		if err := xml.Unmarshal([]byte(conn.IdpMetadataXML), idpMetadata); err == nil {
			sp.IDPMetadata = idpMetadata
		}
	} else if conn.IdpCertificate != "" {
		idpDescriptor := &crewjamsaml.EntityDescriptor{
			EntityID: conn.IdpEntityID,
			IDPSSODescriptors: []crewjamsaml.IDPSSODescriptor{
				{
					SingleSignOnServices: []crewjamsaml.Endpoint{
						{Binding: crewjamsaml.HTTPRedirectBinding, Location: conn.IdpSingleSignOn},
					},
				},
			},
		}

		if block, _ := pem.Decode([]byte(conn.IdpCertificate)); block != nil {
			idpDescriptor.IDPSSODescriptors[0].KeyDescriptors = append(
				idpDescriptor.IDPSSODescriptors[0].KeyDescriptors,
				crewjamsaml.KeyDescriptor{
					Use: "signing",
					KeyInfo: crewjamsaml.KeyInfo{
						X509Data: crewjamsaml.X509Data{X509Certificates: []crewjamsaml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(block.Bytes)}}},
					},
				},
			)
		}

		if block, _ := pem.Decode([]byte(conn.IdpEncryptionCertificate)); block != nil {
			idpDescriptor.IDPSSODescriptors[0].KeyDescriptors = append(
				idpDescriptor.IDPSSODescriptors[0].KeyDescriptors,
				crewjamsaml.KeyDescriptor{
					Use: "encryption",
					KeyInfo: crewjamsaml.KeyInfo{
						X509Data: crewjamsaml.X509Data{X509Certificates: []crewjamsaml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(block.Bytes)}}},
					},
				},
			)
		}

		sp.IDPMetadata = idpDescriptor
	}

	knownIDs := []string{}
	if possibleRequestID != "" {
		knownIDs = append(knownIDs, possibleRequestID)
	}

	// crewjam builds its own goxmldsig validation context internally, which accepts
	// SHA-1. Override its verification with the inbound algorithm policy: the custom
	// verifier pre-inspects the signature/digest algorithms (rejecting SHA-1 by
	// default) and then delegates the actual crypto to that same context.
	sp.SignatureVerifier = signatureAlgorithmVerifier{policy: s.signaturePolicy()}

	assertion, err := sp.ParseResponse(req, knownIDs)
	if err != nil {
		return nil, "", fmt.Errorf("validation failed: %w", err)
	}

	if err := s.replayRepo.CheckAndSaveMessageID(ctx, assertion.ID, tenantID, 1*time.Hour); err != nil {
		return nil, "", fmt.Errorf("security alert (replay detected): %w", err)
	}

	relayState := req.FormValue("RelayState")
	return assertion, relayState, nil
}

func (s *samlBuilderUseCase) GetIdentityProvider(ctx context.Context, tenantID string) (*crewjamsaml.IdentityProvider, error) {
	baseURLStr := fmt.Sprintf("%s/t/%s/saml", s.Config.BaseIssuerURL, tenantID)

	metadataURL, _ := url.Parse(baseURLStr + "/idp/metadata")
	ssoURL, _ := url.Parse(baseURLStr + "/idp/sso")
	logoutURL, _ := url.Parse(baseURLStr + "/idp/slo")

	privKey, cert, _, err := s.KeyMgr.GetActiveKeys(ctx, "sig")
	if err != nil {
		return nil, fmt.Errorf("failed to load active signing key: %w", err)
	}
	if privKey == nil {
		return nil, errors.New("active signing key is nil")
	}
	// Sign with, and advertise, the certificate stored for the active signing key
	// so IdP metadata and issued assertions present a stable certificate. Fall
	// back to a self-signed certificate only when none is stored (e.g. a key that
	// was imported or rotated without an accompanying certificate).
	if cert == nil {
		cert, err = s.generateSelfSignedCert(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to generate idp cert: %w", err)
		}
	}

	idp := &crewjamsaml.IdentityProvider{
		Key:                     privKey,
		Certificate:             cert,
		MetadataURL:             *metadataURL,
		SSOURL:                  *ssoURL,
		LogoutURL:               *logoutURL,
		SignatureMethod:         "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		ServiceProviderProvider: s,
		AssertionMaker:          &persistentAssertionMaker{},
	}

	return idp, nil
}

func (s *samlBuilderUseCase) GetServiceProvider(r *http.Request, serviceProviderID string) (*crewjamsaml.EntityDescriptor, error) {
	samlClient, err := s.clientRepo.GetByEntity(serviceProviderID)
	if err != nil {
		return nil, fmt.Errorf("service provider not found: %s", serviceProviderID)
	}

	spMetadata := &crewjamsaml.EntityDescriptor{
		EntityID: serviceProviderID,
		SPSSODescriptors: []crewjamsaml.SPSSODescriptor{
			{
				SSODescriptor: crewjamsaml.SSODescriptor{
					RoleDescriptor: crewjamsaml.RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors:             []crewjamsaml.KeyDescriptor{},
					},
				},
				AssertionConsumerServices: []crewjamsaml.IndexedEndpoint{
					{
						Binding:  crewjamsaml.HTTPPostBinding,
						Location: samlClient.ACSURL,
						Index:    1,
					},
				},
			},
		},
	}

	encCert := samlClient.SPEncryptionCertificate
	if encCert == "" {
		encCert = samlClient.SPCertificate
	}
	if encCert != "" {
		block, _ := pem.Decode([]byte(encCert))
		if block != nil {
			certStr := base64.StdEncoding.EncodeToString(block.Bytes)
			keyDescriptor := crewjamsaml.KeyDescriptor{
				Use: "encryption",
				KeyInfo: crewjamsaml.KeyInfo{
					X509Data: crewjamsaml.X509Data{
						X509Certificates: []crewjamsaml.X509Certificate{{Data: certStr}},
					},
				},
			}
			spMetadata.SPSSODescriptors[0].KeyDescriptors = append(spMetadata.SPSSODescriptors[0].KeyDescriptors, keyDescriptor)
		}
	}

	if samlClient.SPCertificate != "" {
		block, _ := pem.Decode([]byte(samlClient.SPCertificate))
		if block != nil {
			certStr := base64.StdEncoding.EncodeToString(block.Bytes)
			keyDescriptor := crewjamsaml.KeyDescriptor{
				Use: "signing",
				KeyInfo: crewjamsaml.KeyInfo{
					X509Data: crewjamsaml.X509Data{
						X509Certificates: []crewjamsaml.X509Certificate{{Data: certStr}},
					},
				},
			}
			spMetadata.SPSSODescriptors[0].KeyDescriptors = append(spMetadata.SPSSODescriptors[0].KeyDescriptors, keyDescriptor)

		}
	}

	return spMetadata, nil
}

func (s *samlBuilderUseCase) ParseAuthnRequest(ctx context.Context, tenantID string, req *http.Request) (*crewjamsaml.AuthnRequest, error) {
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

	var authReq crewjamsaml.AuthnRequest
	if err := xml.Unmarshal(xmlBytes, &authReq); err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth request: %w", err)
	}

	if err := s.replayRepo.CheckAndSaveMessageID(ctx, authReq.ID, tenantID, 15*time.Minute); err != nil {
		return nil, fmt.Errorf("security alert (replay detected): %w", err)
	}

	issuer := authReq.Issuer.Value
	if issuer == "" {
		return nil, fmt.Errorf("missing issuer in AuthnRequest")
	}

	spClient, err := s.clientRepo.GetByTenantAndEntityID(ctx, tenantID, issuer)
	if err != nil {
		return nil, fmt.Errorf("unknown service provider: %s", issuer)
	}

	if spClient.SPCertificate != "" {
		if isRedirectBinding {
			// The unified verifier owns PEM/certificate parsing so every redirect
			// failure path is handled in one place; the policy gate rejects a
			// disabled algorithm (SHA-1 by default) before the crypto.
			if err := s.VerifyInboundRedirectSignature(req, spClient.SPCertificate); err != nil {
				return nil, fmt.Errorf("signature validation failed: %w", err)
			}
		} else {
			block, _ := pem.Decode([]byte(spClient.SPCertificate))
			if block == nil {
				return nil, fmt.Errorf("invalid SP certificate format")
			}
			spCert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse SP certificate: %w", err)
			}
			if err := verifyPostSignature(xmlBytes, spCert, s.signaturePolicy()); err != nil {
				return nil, fmt.Errorf("xml signature validation failed: %w", err)
			}
		}
	}

	return &authReq, nil
}

func (s *samlBuilderUseCase) GenerateSAMLResponse(ctx context.Context, tenantID string, authReq *crewjamsaml.AuthnRequest, sp *model.SAMLClient, userAttributes map[string]interface{}, relayState string) (string, error) {
	idp, err := s.GetIdentityProvider(ctx, tenantID)
	if err != nil {
		return "", err
	}

	// Truncate issuance timestamps to millisecond precision. Go's clock carries
	// nanoseconds, which serialize as xs:dateTime values with up to nine
	// fractional digits; strict readers such as ADFS parse at milliseconds and
	// mishandle finer values. Truncating once here covers every field derived
	// from now (all use now or now.Add(...)). Truncation moves the instant
	// backwards by under a millisecond, so no validity window is lengthened.
	now := s.now().Truncate(time.Millisecond)
	subject := "unknown"
	if v, ok := userAttributes[utils.SAMLNameIDSubjectAttribute].(string); ok {
		subject = v
	} else if v, ok := userAttributes["sub"].(string); ok {
		subject = v
	} else if v, ok := userAttributes["email"].(string); ok {
		subject = v
	}

	nameIDFormat := string(crewjamsaml.UnspecifiedNameIDFormat)
	if authReq.NameIDPolicy != nil && authReq.NameIDPolicy.Format != nil {
		requestedFormat := *authReq.NameIDPolicy.Format
		if requestedFormat != "" {
			nameIDFormat = requestedFormat
		}
	}

	var samlStatus crewjamsaml.Status
	var assertion *crewjamsaml.Assertion
	nameIDValue := subject

	switch nameIDFormat {
	case string(crewjamsaml.UnspecifiedNameIDFormat):
		// Supported default. The NameID value is the subject as-is; this case is
		// handled explicitly so it is a supported outcome, not a fall-through.

	case string(crewjamsaml.EmailAddressNameIDFormat):
		email, ok := userAttributes["email"].(string)
		if !ok || email == "" {
			samlStatus = crewjamsaml.Status{
				StatusCode: crewjamsaml.StatusCode{
					Value: crewjamsaml.StatusRequester,
					StatusCode: &crewjamsaml.StatusCode{
						Value: "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy",
					},
				},
				StatusMessage: &crewjamsaml.StatusMessage{
					Value: "Required email address is missing for the user",
				},
			}
		} else {
			nameIDValue = email
		}

	case string(crewjamsaml.TransientNameIDFormat):
		nameIDValue = uuid.New().String()

	default:
		// Fail closed: an unsupported NameID format must never yield an assertion
		// labelled with a format the IdP did not actually produce (SAML Core
		// 3.4.1.1). Persistent lands here — it is not satisfiable until real
		// opaque pairwise identifiers exist.
		samlStatus = crewjamsaml.Status{
			StatusCode: crewjamsaml.StatusCode{
				Value: crewjamsaml.StatusRequester,
				StatusCode: &crewjamsaml.StatusCode{
					Value: "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy",
				},
			},
			StatusMessage: &crewjamsaml.StatusMessage{
				Value: fmt.Sprintf("Requested NameID format is not supported: %s", nameIDFormat),
			},
		}
	}

	if samlStatus.StatusCode.Value == "" {
		samlStatus = crewjamsaml.Status{
			StatusCode: crewjamsaml.StatusCode{
				Value: crewjamsaml.StatusSuccess,
			},
		}

		authnContextClass := "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
		if amrList, ok := userAttributes["amr"].([]string); ok {
			for _, m := range amrList {
				if m == "ext" || m == "mfa" {
					authnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession"
				}
			}
		} else if amrList, ok := userAttributes["amr"].([]interface{}); ok {
			for _, m := range amrList {
				if m == "ext" || m == "mfa" {
					authnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession"
				}
			}
		}

		assertion = &crewjamsaml.Assertion{
			ID:           fmt.Sprintf("id-%d", now.UnixNano()),
			IssueInstant: now,
			Version:      "2.0",
			Issuer: crewjamsaml.Issuer{
				Value: idp.MetadataURL.String(),
			},
			Subject: &crewjamsaml.Subject{
				NameID: &crewjamsaml.NameID{
					Format: nameIDFormat,
					Value:  nameIDValue,
				},
				SubjectConfirmations: []crewjamsaml.SubjectConfirmation{
					{
						Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
						SubjectConfirmationData: &crewjamsaml.SubjectConfirmationData{
							InResponseTo: authReq.ID,
							NotOnOrAfter: now.Add(5 * time.Minute),
							Recipient:    authReq.AssertionConsumerServiceURL,
						},
					},
				},
			},
			Conditions: &crewjamsaml.Conditions{
				NotBefore:    now.Add(-5 * time.Minute),
				NotOnOrAfter: now.Add(5 * time.Minute),
				AudienceRestrictions: []crewjamsaml.AudienceRestriction{
					{
						Audience: crewjamsaml.Audience{Value: authReq.Issuer.Value},
					},
				},
			},
			AuthnStatements: []crewjamsaml.AuthnStatement{
				{
					AuthnInstant: now,
					SessionIndex: fmt.Sprintf("id-%d", now.UnixNano()),
					AuthnContext: crewjamsaml.AuthnContext{
						AuthnContextClassRef: &crewjamsaml.AuthnContextClassRef{
							Value: authnContextClass,
						},
					},
				},
			},
			AttributeStatements: []crewjamsaml.AttributeStatement{
				{
					Attributes: []crewjamsaml.Attribute{},
				},
			},
		}

		for k, v := range userAttributes {
			if k == utils.SAMLNameIDSubjectAttribute {
				continue
			}

			var attrValues []crewjamsaml.AttributeValue

			switch val := v.(type) {
			case []string:
				for _, item := range val {
					attrValues = append(attrValues, crewjamsaml.AttributeValue{
						Type:  "xs:string",
						Value: item,
					})
				}
			case []interface{}:
				for _, item := range val {
					attrValues = append(attrValues, crewjamsaml.AttributeValue{
						Type:  "xs:string",
						Value: fmt.Sprintf("%v", item),
					})
				}
			default:
				attrValues = append(attrValues, crewjamsaml.AttributeValue{
					Type:  "xs:string",
					Value: fmt.Sprintf("%v", val),
				})
			}

			// Resolve NameFormat: an explicit, valid rule override wins; otherwise
			// derive it from the output attribute name (the mapping map key = k).
			// A stored value that is not a valid attrname-format is treated as
			// unset, so an invalid string can never reach the assertion.
			nameFormat := model.AttributeNameFormatFor(k)
			if rule, ok := sp.AttributeMapping[k]; ok && model.IsValidAttributeNameFormat(rule.NameFormat) {
				nameFormat = rule.NameFormat
			}

			assertion.AttributeStatements[0].Attributes = append(assertion.AttributeStatements[0].Attributes, crewjamsaml.Attribute{
				Name:       k,
				NameFormat: nameFormat,
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

		if sp.EncryptAssertion {
			targetCert := sp.SPEncryptionCertificate
			if targetCert == "" {
				targetCert = sp.SPCertificate
			}

			if targetCert != "" {
				block, _ := pem.Decode([]byte(targetCert))
				if block != nil {
					spCert, err := x509.ParseCertificate(block.Bytes)
					if err == nil {
						assertBytesToEncrypt, werr := docAssert.WriteToBytes()
						if werr != nil {
							return "", werr
						}
						// Declare xmlns:xs INSIDE the assertion, before encryption, so
						// the xsi:type="xs:string" QName resolves in the assertion the SP
						// recovers on decrypt. The response-root declaration is outside
						// the ciphertext and cannot reach the decrypted assertion. Added
						// after signing; exclusive C14N excludes xs from the assertion
						// digest, so the assertion signature still verifies after decrypt.
						assertBytesToEncrypt, werr = declareXMLSchemaNamespace(assertBytesToEncrypt)
						if werr != nil {
							return "", werr
						}
						encryptedElem, err := encryptAssertionBytes(assertBytesToEncrypt, spCert)
						if err != nil {
							return "", fmt.Errorf("failed to encrypt assertion: %w", err)
						}
						finalAssertionElement = encryptedElem
					}
				}
			}
		}
	}

	response := &crewjamsaml.Response{
		ID:           fmt.Sprintf("resp-%d", now.UnixNano()),
		InResponseTo: authReq.ID,
		IssueInstant: now,
		Version:      "2.0",
		Destination:  authReq.AssertionConsumerServiceURL,
		Issuer: &crewjamsaml.Issuer{
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

	// Declare xmlns:xs on the response root so the xsi:type="xs:string" QName that
	// encoding/xml emits on every AttributeValue resolves to an in-scope binding.
	// Go declares the XMLSchema-instance namespace (it names the type attribute)
	// but never xs (which appears only inside the attribute value), leaving a
	// dangling QName that fails XSD validation. This is done AFTER signing: the
	// signing canonicalizer is exclusive C14N, which strips a namespace not used
	// in any element or attribute name from the element in place, so a
	// before-signing declaration does not survive into the serialized output. On
	// verification the same exclusive C14N excludes xs from every digest (response
	// and any nested assertion), so adding it here does not affect any signature.
	finalXMLBytes, err = declareXMLSchemaNamespace(finalXMLBytes)
	if err != nil {
		return "", err
	}

	b64Resp := base64.StdEncoding.EncodeToString(finalXMLBytes)
	return buildHTMLForm(authReq.AssertionConsumerServiceURL, b64Resp, relayState), nil
}

// GenerateSAMLErrorResponse builds a SAML Response carrying a top-level error
// Status and NO assertion, delivered through the same auto-POST form as a success
// Response. It is the fail-closed path (SAML Core 3.2.2.2) for when the identity
// provider cannot produce a usable assertion — e.g. a configured attribute
// mapping that yields zero attributes. statusMessage is surfaced to the SP in the
// StatusMessage element and MUST name a failure category only; callers must never
// pass a claim name or value. The Response is signed when the SP requires it, so
// the SP can trust the failure signal exactly as it trusts a success.
func (s *samlBuilderUseCase) GenerateSAMLErrorResponse(ctx context.Context, tenantID string, authReq *crewjamsaml.AuthnRequest, sp *model.SAMLClient, topLevelStatus, statusMessage, relayState string) (string, error) {
	idp, err := s.GetIdentityProvider(ctx, tenantID)
	if err != nil {
		return "", err
	}
	now := s.now().Truncate(time.Millisecond)

	response := &crewjamsaml.Response{
		ID:           fmt.Sprintf("resp-%d", now.UnixNano()),
		InResponseTo: authReq.ID,
		IssueInstant: now,
		Version:      "2.0",
		Destination:  authReq.AssertionConsumerServiceURL,
		Issuer: &crewjamsaml.Issuer{
			Value: idp.MetadataURL.String(),
		},
		Status: crewjamsaml.Status{
			StatusCode: crewjamsaml.StatusCode{
				Value: topLevelStatus,
			},
			StatusMessage: &crewjamsaml.StatusMessage{
				Value: statusMessage,
			},
		},
	}

	respBytes, err := xml.Marshal(response)
	if err != nil {
		return "", err
	}
	docResp := etree.NewDocument()
	if err := docResp.ReadFromBytes(respBytes); err != nil {
		return "", fmt.Errorf("failed to parse response xml: %w", err)
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

// declareXMLSchemaNamespace adds xmlns:xs="http://www.w3.org/2001/XMLSchema" to
// the root element of a signed SAML document so the xsi:type="xs:string" QName on
// descendant AttributeValues resolves. It must run after signing (see caller).
func declareXMLSchemaNamespace(xmlBytes []byte) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, fmt.Errorf("failed to parse response xml for namespace declaration: %w", err)
	}
	doc.Root().CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
	out, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to re-serialize response xml: %w", err)
	}
	return out, nil
}

func (s *samlBuilderUseCase) RegisterConnection(ctx context.Context, tenantID, name, metadataXML string) (*model.SAMLConnection, error) {
	meta := &crewjamsaml.EntityDescriptor{}
	if err := xml.Unmarshal([]byte(metadataXML), meta); err != nil {
		return nil, err
	}

	//TODO
	conn := &model.SAMLConnection{
		TenantID:       tenantID,
		Name:           name,
		IdpMetadataXML: metadataXML,
		IdpEntityID:    meta.EntityID,
		Active:         true,
	}
	return conn, s.connRepo.Create(ctx, conn)
}

func (s *samlBuilderUseCase) ParseLogoutRequest(req *http.Request) (*crewjamsaml.LogoutRequest, error) {
	encoded := req.URL.Query().Get("SAMLRequest")
	isRedirect := true
	if encoded == "" {
		encoded = req.PostFormValue("SAMLRequest")
		isRedirect = false
	}
	if encoded == "" {
		return nil, errors.New("missing SAMLRequest parameter for SLO")
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		unescaped, _ := url.QueryUnescape(encoded)
		decoded, _ = base64.StdEncoding.DecodeString(unescaped)
	}

	var xmlBytes []byte
	if isRedirect {
		flater := flate.NewReader(bytes.NewReader(decoded))
		xmlBytes, _ = io.ReadAll(flater)
		err := flater.Close()
		if err != nil {
			return nil, err
		}
	} else {
		xmlBytes = decoded
	}

	var logoutReq crewjamsaml.LogoutRequest
	if err := xml.Unmarshal(xmlBytes, &logoutReq); err != nil {
		return nil, err
	}
	return &logoutReq, nil
}

func (s *samlBuilderUseCase) GenerateLogoutResponse(ctx context.Context, tenantID string, req *crewjamsaml.LogoutRequest, sp *model.SAMLClient, relayState string) (string, error) {
	idp, err := s.GetIdentityProvider(ctx, tenantID)
	if err != nil {
		return "", err
	}
	// Truncate issuance timestamps to millisecond precision. Go's clock carries
	// nanoseconds, which serialize as xs:dateTime values with up to nine
	// fractional digits; strict readers such as ADFS parse at milliseconds and
	// mishandle finer values. Truncating once here covers every field derived
	// from now (all use now or now.Add(...)). Truncation moves the instant
	// backwards by under a millisecond, so no validity window is lengthened.
	now := s.now().Truncate(time.Millisecond)

	resp := &crewjamsaml.LogoutResponse{
		ID:           fmt.Sprintf("resp-%d", now.UnixNano()),
		InResponseTo: req.ID,
		IssueInstant: now,
		Version:      "2.0",
		Destination:  sp.SLOURL,
		Issuer: &crewjamsaml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  idp.MetadataURL.String(),
		},
		Status: crewjamsaml.Status{
			StatusCode: crewjamsaml.StatusCode{
				Value: crewjamsaml.StatusSuccess,
			},
		},
	}

	respBytes, err := xml.Marshal(resp)
	if err != nil {
		return "", err
	}
	docResp := etree.NewDocument()
	if err := docResp.ReadFromBytes(respBytes); err != nil {
		return "", err
	}
	finalXMLBytes, err := docResp.WriteToBytes()
	if err != nil {
		return "", err
	}

	if sp.SignResponse {
		finalXMLBytes, err = s.signElementXML(finalXMLBytes, idp.Key.(*rsa.PrivateKey), idp.Certificate)
		if err != nil {
			return "", fmt.Errorf("failed to sign logout response: %w", err)
		}
	}

	b64Resp := base64.StdEncoding.EncodeToString(finalXMLBytes)
	return buildHTMLForm(sp.SLOURL, b64Resp, relayState), nil
}

func (s *samlBuilderUseCase) VerifyRelayState(ctx context.Context, tenantID, encryptedState, csrfToken string) (*security.FederationStatePayload, error) {
	return s.stateProvider.Verify(ctx, encryptedState, security.VerifyFederationStateInput{
		ExpectedAction: security.FederationActionSAMLLogin,
		ExpectedTenant: tenantID,
		CSRFToken:      csrfToken,
	})
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

// signElementXML applies an enveloped signature and places ds:Signature
// immediately after the root's Issuer child. The root MUST have an Issuer child;
// otherwise the function returns an error rather than failing open, since emitting
// the signature in the wrong position would silently reintroduce the strict-reader
// (ADFS) ordering defect this function exists to prevent.
func (s *samlBuilderUseCase) signElementXML(xmlBytes []byte, key *rsa.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	signingContext, err := goxmldsig.NewSigningContext(key, [][]byte{cert.Raw})
	if err != nil {
		return nil, err
	}

	// Use exclusive C14N 1.0 with an empty inclusive-namespace prefix list.
	// goxmldsig defaults to Canonical XML 1.1, which strict SAML readers such as
	// ADFS support poorly. No prefix-list entries are needed on this path.
	signingContext.Canonicalizer = goxmldsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

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

	// Resolve the signature that belongs to THIS root only: its direct
	// ds:Signature child (SignEnveloped appends it as the last child). When
	// signing a Response that already contains a signed Assertion, the inner
	// Assertion signature is nested and must not be touched here. A descendant
	// search would wrongly match the inner signature, and mutating inner content
	// after the outer digest is computed would invalidate the outer signature.
	var signatureEl *etree.Element
	for _, child := range signedElement.ChildElements() {
		if child.Tag == "Signature" {
			signatureEl = child
			break
		}
	}
	if signatureEl == nil {
		return nil, errors.New("signed element is missing its Signature child")
	}

	// Scoped lookups: only ever traverse this root's own signature subtree.
	findChild := func(parent *etree.Element, tag string) *etree.Element {
		for _, c := range parent.ChildElements() {
			if c.Tag == tag {
				return c
			}
		}
		return nil
	}
	var collect func(el *etree.Element, tag string, out *[]*etree.Element)
	collect = func(el *etree.Element, tag string, out *[]*etree.Element) {
		for _, c := range el.ChildElements() {
			if c.Tag == tag {
				*out = append(*out, c)
			}
			collect(c, tag, out)
		}
	}

	// Emit ds:KeyName as the first child of KeyInfo, carrying the signing
	// certificate's Subject DN. KeyInfo lives inside the Signature and is
	// excluded from the enveloped digest, so this is safe after signing.
	if keyInfo := findChild(signatureEl, "KeyInfo"); keyInfo != nil {
		keyName := etree.NewElement("KeyName")
		keyName.Space = "ds"
		keyName.SetText(cert.Subject.String())
		keyInfo.InsertChildAt(0, keyName)
	}

	// Strip newlines, carriage returns and spaces from the base64 text of the
	// certificate and signature nodes belonging to THIS signature only.
	strip := func(v string) string {
		return strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(v)
	}
	var certNodes, sigValueNodes []*etree.Element
	collect(signatureEl, "X509Certificate", &certNodes)
	collect(signatureEl, "SignatureValue", &sigValueNodes)
	for _, n := range certNodes {
		n.SetText(strip(n.Text()))
	}
	for _, n := range sigValueNodes {
		n.SetText(strip(n.Text()))
	}

	// Relocate the signature to immediately after Issuer, as SAML 2.0 requires.
	// The enveloped-signature transform excludes the Signature element from the
	// digest by identity, not position, so moving it does not affect validity.
	// goxmldsig appends the Signature via a raw slice append and never sets its
	// parent pointer, so RemoveChild (which checks the parent) is a no-op here;
	// locate both nodes by scanning the child-token slice and remove by index.
	sigIndex, issuerIndex := -1, -1
	for i, tok := range signedElement.Child {
		el, ok := tok.(*etree.Element)
		if !ok {
			continue
		}
		if el == signatureEl {
			sigIndex = i
		} else if el.Tag == "Issuer" && issuerIndex == -1 {
			issuerIndex = i
		}
	}
	if issuerIndex == -1 {
		return nil, errors.New("cannot place signature: root has no Issuer child")
	}
	if sigIndex == -1 {
		return nil, errors.New("cannot place signature: signature child not found")
	}
	// The Signature is appended last, so sigIndex > issuerIndex and removing it
	// does not shift issuerIndex.
	signedElement.RemoveChildAt(sigIndex)
	signedElement.InsertChildAt(issuerIndex+1, signatureEl)

	newDoc := etree.NewDocument()
	newDoc.SetRoot(signedElement)
	return newDoc.WriteToBytes()
}

// rawQueryParam returns the value substring for key exactly as it appears in the
// raw query string — still percent-encoded, never decoded and re-encoded. The
// second return reports whether the key was present at all. Parameter names in
// the SAML redirect binding are plain ASCII, so the name is compared literally.
func rawQueryParam(rawQuery, key string) (string, bool) {
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		name := pair
		value := ""
		if eq := strings.IndexByte(pair, '='); eq >= 0 {
			name = pair[:eq]
			value = pair[eq+1:]
		}
		if name == key {
			return value, true
		}
	}
	return "", false
}

// VerifyRedirectSignature verifies the signature on a SAML HTTP-Redirect binding
// message (SAMLRequest or SAMLResponse) per SAML 2.0 Bindings §3.4.4.1.
//
// The signature is computed by the sender over the URL-encoded query string it
// constructed, in the exact order SAMLRequest|SAMLResponse, then RelayState (only
// if present), then SigAlg. Percent-encoding is NOT canonical: %20 vs '+', hex
// case, and the treatment of ~ ! * ( ) all yield different octets for the same
// logical value. Reconstructing the signed string with url.QueryEscape therefore
// silently fails whenever the sender's encoding differs from Go's. To avoid that,
// this function verifies over the RAW value substrings taken verbatim from the
// request's query string; only SigAlg and Signature are decoded, and never fed
// back into the signed string.
//
// It fails closed on every error path. Error messages name the failure category
// only and never include the query, the signature, the certificate, or any
// parameter value.
func VerifyRedirectSignature(req *http.Request, certPEM string) error {
	rawQuery := req.URL.RawQuery

	// Exactly one message parameter must be present; neither or both is invalid.
	samlReqRaw, hasReq := rawQueryParam(rawQuery, "SAMLRequest")
	samlResRaw, hasRes := rawQueryParam(rawQuery, "SAMLResponse")
	if hasReq == hasRes {
		return errors.New("exactly one of SAMLRequest or SAMLResponse is required")
	}
	messageField, messageRaw := "SAMLRequest", samlReqRaw
	if hasRes {
		messageField, messageRaw = "SAMLResponse", samlResRaw
	}

	sigAlgRaw, hasSigAlg := rawQueryParam(rawQuery, "SigAlg")
	if !hasSigAlg {
		return errors.New("missing SigAlg parameter")
	}
	signatureRaw, hasSig := rawQueryParam(rawQuery, "Signature")
	if !hasSig {
		return errors.New("missing Signature parameter")
	}
	relayStateRaw, hasRelayState := rawQueryParam(rawQuery, "RelayState")

	// Decode SigAlg (to select the digest) and Signature (to compare) — but never
	// re-encode them back into the signed string.
	sigAlg, err := url.QueryUnescape(sigAlgRaw)
	if err != nil {
		return errors.New("malformed SigAlg encoding")
	}
	signatureEncoded, err := url.QueryUnescape(signatureRaw)
	if err != nil {
		return errors.New("malformed Signature encoding")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(signatureEncoded)
	if err != nil {
		return errors.New("invalid signature base64")
	}

	// Rebuild the signed string from the RAW received octets, in the specified
	// order. RelayState is included only when the sender sent it.
	var signed strings.Builder
	signed.WriteString(messageField)
	signed.WriteByte('=')
	signed.WriteString(messageRaw)
	if hasRelayState {
		signed.WriteString("&RelayState=")
		signed.WriteString(relayStateRaw)
	}
	signed.WriteString("&SigAlg=")
	signed.WriteString(sigAlgRaw)

	// Exact URI match, no suffix matching. The accepted set is the union of the two
	// former implementations (SHA-1, SHA-256, SHA-512): the handler accepted
	// SHA-512, the use case did not, and the union preserves behavioural
	// equivalence for both call sites without widening either beyond what it had.
	var hashAlg crypto.Hash
	switch sigAlg {
	case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
		hashAlg = crypto.SHA1
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
		hashAlg = crypto.SHA256
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":
		hashAlg = crypto.SHA512
	default:
		return errors.New("unsupported signature algorithm")
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.New("failed to decode SP certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("failed to parse SP certificate")
	}
	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("SP certificate public key is not RSA")
	}

	hasher := hashAlg.New()
	hasher.Write([]byte(signed.String()))
	if err := rsa.VerifyPKCS1v15(rsaPub, hashAlg, hasher.Sum(nil), sigBytes); err != nil {
		return errors.New("signature verification failed")
	}
	return nil
}

// VerifyInboundRedirectSignature verifies an inbound HTTP-Redirect binding
// signature under Shyntr's inbound signature-algorithm policy. It rejects a
// disabled algorithm (SHA-1 by default) first — failing closed with an error that
// names the algorithm category only — then delegates the cryptographic
// verification to VerifyRedirectSignature, which is unchanged and policy-agnostic.
func (s *samlBuilderUseCase) VerifyInboundRedirectSignature(req *http.Request, certPEM string) error {
	if err := s.signaturePolicy().checkRedirectSignatureAlgorithm(req); err != nil {
		return err
	}
	return VerifyRedirectSignature(req, certPEM)
}

// verifyPostSignature validates an embedded (POST-binding) XML-DSig signature. It
// first applies the inbound algorithm policy (rejecting SHA-1 signature/digest by
// default) by pre-inspecting the SignatureMethod/DigestMethod URIs, since goxmldsig
// exposes no algorithm allow-list, then performs the cryptographic validation.
func verifyPostSignature(xmlBytes []byte, cert *x509.Certificate, policy signatureAlgorithmPolicy) error {
	ks := &SingleCertStore{Cert: cert}
	ctx := goxmldsig.NewDefaultValidationContext(ks)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return err
	}
	if doc.Root() == nil {
		return errors.New("empty xml doc")
	}
	if err := policy.checkEmbeddedSignatureAlgorithms(doc.Root()); err != nil {
		return err
	}
	_, err := ctx.Validate(doc.Root())
	return err
}

func (s *samlBuilderUseCase) generateSelfSignedCert(key *rsa.PrivateKey) (*x509.Certificate, error) {
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

func (m *persistentAssertionMaker) MakeAssertion(req *crewjamsaml.IdpAuthnRequest, session *crewjamsaml.Session) error {
	err := m.DefaultAssertionMaker.MakeAssertion(req, session)
	if err != nil {
		return err
	}

	if req.Assertion != nil && req.Assertion.Subject != nil && req.Assertion.Subject.NameID != nil {
		req.Assertion.Subject.NameID.Format = string(crewjamsaml.PersistentNameIDFormat)
	}

	return nil
}
