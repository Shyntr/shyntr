package models

import (
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/lib/pq"
)

// OAuth2Client represents a registered application with advanced security policies.
type OAuth2Client struct {
	ID       string `gorm:"primaryKey"`
	TenantID string `gorm:"index;not null"`
	AppID    string `gorm:"index"`
	Secret   string `gorm:"not null"`

	// --- Protocol Flows ---
	RedirectURIs  pq.StringArray `gorm:"type:text[]"`
	GrantTypes    pq.StringArray `gorm:"type:text[]"` // authorization_code, refresh_token, client_credentials, urn:ietf:params:oauth:grant-type:jwt-bearer
	ResponseTypes pq.StringArray `gorm:"type:text[]"` // code, token, id_token

	// --- Access Control ---
	Scopes   pq.StringArray `gorm:"type:text[]"`
	Audience pq.StringArray `gorm:"type:text[]"` // YENİ: Token'ın geçerli olduğu hedef servisler

	// --- Security Settings ---
	Public                  bool           // True for SPA/Mobile (No secret required)
	TokenEndpointAuthMethod string         `gorm:"default:'client_secret_basic'"` // YENİ: client_secret_basic, client_secret_post, private_key_jwt, none
	EnforcePKCE             bool           `gorm:"default:false"`                 // YENİ: PKCE kullanmayan istekleri reddet
	AllowedCORSOrigins      pq.StringArray `gorm:"type:text[]"`                   // YENİ: Browser tabanlı istekler için CORS whitelist

	// --- Advanced ---
	PostLogoutRedirectURIs pq.StringArray      `gorm:"type:text[]"`
	JSONWebKeys            *jose.JSONWebKeySet `gorm:"type:jsonb"` // private_key_jwt için Public Key seti
	SkipConsent            bool                `gorm:"default:false"`
	SubjectType            string              `gorm:"default:'public'"` // YENİ: public veya pairwise

	// --- Lifespans (Override Defaults) ---
	AccessTokenLifespan  string `gorm:"default:''"`
	RefreshTokenLifespan string `gorm:"default:''"`
	IDTokenLifespan      string `gorm:"default:''"`

	CreatedAt time.Time
	UpdatedAt time.Time
}
