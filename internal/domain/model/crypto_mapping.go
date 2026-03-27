package model

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

type KeyState string

const (
	KeyStatePending KeyState = "PENDING"
	KeyStateActive  KeyState = "ACTIVE"
	KeyStatePassive KeyState = "PASSIVE"
	KeyStateRevoked KeyState = "REVOKED"
)

type CryptoKey struct {
	ID        string     `json:"id" example:"sig-5f8a9b2"`
	Use       string     `json:"use" example:"sig"` // 'sig' or 'enc'
	State     KeyState   `json:"state" example:"ACTIVE"`
	Algorithm string     `json:"algorithm" example:"RS256"`
	KeyData   []byte     `json:"-"`
	CertData  string     `json:"cert_data,omitempty" example:"-----BEGIN CERTIFICATE..."`
	CreatedAt time.Time  `json:"created_at" example:"2026-03-18T12:00:00Z"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" example:"2027-03-18T12:00:00Z"`
}

type BlacklistedJTI struct {
	JTI       string
	ExpiresAt time.Time
}

type AttributeMappingRule struct {
	Source       string   `json:"source"`
	Target       string   `json:"target"`
	Type         string   `json:"type"`
	TargetScopes []string `json:"target_scopes,omitempty"`
	Fallback     string   `json:"fallback,omitempty"`
	Value        string   `json:"value,omitempty"`
}

// JWTSession represents explicitly stored JWT states if required by custom flows or specific Fosite implementations.
type JWTSession struct {
	*openid.DefaultSession
	JWTClaims     *jwt.JWTClaims `json:"jwt_claims"`
	JWTHeader     *jwt.Headers   `json:"jwt_header"`
	TokenFamilyID string         `json:"token_family_id"`
}

var _ fosite.Session = (*JWTSession)(nil)

func NewJWTSession(subject string, familyID string) *JWTSession {
	return &JWTSession{
		DefaultSession: &openid.DefaultSession{
			Claims:  &jwt.IDTokenClaims{Subject: subject},
			Headers: &jwt.Headers{Extra: make(map[string]interface{})},
			Subject: subject,
		},
		JWTClaims:     &jwt.JWTClaims{Subject: subject, Extra: make(map[string]interface{})},
		JWTHeader:     &jwt.Headers{Extra: make(map[string]interface{})},
		TokenFamilyID: familyID,
	}
}

func (s *JWTSession) GetJWTClaims() jwt.JWTClaimsContainer {
	if s.JWTClaims == nil {
		s.JWTClaims = &jwt.JWTClaims{Extra: make(map[string]interface{})}
	}
	return s.JWTClaims
}

func (s *JWTSession) GetJWTHeader() *jwt.Headers {
	if s.JWTHeader == nil {
		s.JWTHeader = &jwt.Headers{Extra: make(map[string]interface{})}
	}
	return s.JWTHeader
}

func (s *JWTSession) Clone() fosite.Session {
	if s == nil {
		return nil
	}

	cloned := &JWTSession{
		JWTClaims:     &jwt.JWTClaims{Extra: make(map[string]interface{})},
		JWTHeader:     &jwt.Headers{Extra: make(map[string]interface{})},
		TokenFamilyID: s.TokenFamilyID,
	}

	if s.DefaultSession != nil {
		cloned.DefaultSession = s.DefaultSession.Clone().(*openid.DefaultSession)
	}

	if s.JWTClaims != nil {
		cloned.JWTClaims.Subject = s.JWTClaims.Subject
		cloned.JWTClaims.Issuer = s.JWTClaims.Issuer
		cloned.JWTClaims.Audience = s.JWTClaims.Audience
		cloned.JWTClaims.JTI = s.JWTClaims.JTI
		cloned.JWTClaims.IssuedAt = s.JWTClaims.IssuedAt
		cloned.JWTClaims.ExpiresAt = s.JWTClaims.ExpiresAt
		cloned.JWTClaims.NotBefore = s.JWTClaims.NotBefore
		for k, v := range s.JWTClaims.Extra {
			cloned.JWTClaims.Extra[k] = v
		}
	}

	if s.JWTHeader != nil {
		for k, v := range s.JWTHeader.Extra {
			cloned.JWTHeader.Extra[k] = v
		}
	}

	return cloned
}

var (
	AllowedJWEAlgs = []jose.KeyAlgorithm{
		jose.RSA_OAEP_256, // Minimum acceptable RSA
		jose.ECDH_ES,      // Preferred for Forward Secrecy
		jose.A256GCMKW,    // Symmetric fallback
	}

	AllowedJWEEncs = []jose.ContentEncryption{
		jose.A256GCM,       // Standard high-assurance
		jose.A128CBC_HS256, // Acceptable fallback
	}
)

// ValidateCipherSuite ensures the client configuration does not request weak cryptography.
func ValidateCipherSuite(alg, enc string) error {
	validAlg := false
	for _, a := range AllowedJWEAlgs {
		if string(a) == alg {
			validAlg = true
			break
		}
	}
	if alg != "" && !validAlg {
		return fmt.Errorf("insecure or unsupported JWE algorithm requested: %s. Must use RSA-OAEP-256, ECDH-ES, or A256GCMKW", alg)
	}

	validEnc := false
	for _, e := range AllowedJWEEncs {
		if string(e) == enc {
			validEnc = true
			break
		}
	}
	if enc != "" && !validEnc {
		return fmt.Errorf("insecure or unsupported JWE encryption requested: %s. Must use A256GCM or A128CBC-HS256", enc)
	}

	return nil
}

// ValidateIncomingJWEHeader prevents Asymmetric Crypto DoS and Zip Bomb attacks
func ValidateIncomingJWEHeader(header jose.Header) error {
	if header.Algorithm == "none" {
		return errors.New("critical security violation: 'none' algorithm is prohibited")
	}

	if header.Algorithm == string(jose.RSA1_5) {
		return errors.New("critical security violation: RSA1_5 is vulnerable to padding oracles and is prohibited")
	}

	// CVE-2024-28180 Protection: Reject compressed payloads unless you have updated go-jose
	// and explicitly configured maximum decompression bounds.
	if header.ExtraHeaders != nil {
		if _, hasZip := header.ExtraHeaders["zip"]; hasZip {
			return errors.New("security violation: JWE compression (zip) is disabled to prevent resource exhaustion (Zip Bomb) attacks")
		}
	}

	return nil
}
