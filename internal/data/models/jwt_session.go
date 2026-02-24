package models

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// JWTSession fulfills Fosite's requirements for both OpenID Connect (ID Token)
// and JWT Access Tokens securely.
type JWTSession struct {
	*openid.DefaultSession
	JWTClaims *jwt.JWTClaims `json:"jwt_claims"`
	JWTHeader *jwt.Headers   `json:"jwt_header"`
}

var _ fosite.Session = (*JWTSession)(nil)
var _ oauth2.JWTSessionContainer = (*JWTSession)(nil)

func NewJWTSession(subject string) *JWTSession {
	return &JWTSession{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject: subject,
			},
			Headers: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
		},
		JWTClaims: &jwt.JWTClaims{
			Subject: subject,
			Extra:   make(map[string]interface{}),
		},
		JWTHeader: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
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
		JWTClaims: &jwt.JWTClaims{Extra: make(map[string]interface{})},
		JWTHeader: &jwt.Headers{Extra: make(map[string]interface{})},
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
