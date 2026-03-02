package models

import (
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/lib/pq"
)

// OAuth2Client represents a registered application with advanced security policies.
type OAuth2Client struct {
	ID       string `gorm:"primaryKey" json:"client_id"`
	TenantID string `gorm:"index;not null" json:"tenant_id"`
	Name     string `gorm:"not null;default:'Unnamed Client'" json:"name"`
	AppID    string `gorm:"index" json:"app_id"`
	Secret   string `gorm:"not null" json:"client_secret,omitempty"`

	// --- Protocol Flows ---
	RedirectURIs  pq.StringArray `gorm:"type:text[]" json:"redirect_uris"`
	GrantTypes    pq.StringArray `gorm:"type:text[]" json:"grant_types"`    // authorization_code, refresh_token...
	ResponseTypes pq.StringArray `gorm:"type:text[]" json:"response_types"` // code, token, id_token
	ResponseModes pq.StringArray `gorm:"type:text[]" json:"response_modes"`

	// --- Access Control ---
	Scopes   pq.StringArray `gorm:"type:text[]" json:"scopes"`
	Audience pq.StringArray `gorm:"type:text[]" json:"audience"`

	// --- Security Settings ---
	Public                  bool           `json:"public"` // True for SPA/Mobile
	TokenEndpointAuthMethod string         `gorm:"default:'client_secret_basic'" json:"token_endpoint_auth_method"`
	EnforcePKCE             bool           `gorm:"default:false" json:"enforce_pkce"`
	AllowedCORSOrigins      pq.StringArray `gorm:"type:text[]" json:"allowed_cors_origins"`

	// --- Advanced ---
	PostLogoutRedirectURIs pq.StringArray      `gorm:"type:text[]" json:"post_logout_redirect_uris"`
	JSONWebKeys            *jose.JSONWebKeySet `gorm:"type:jsonb" json:"jwks,omitempty"`
	SkipConsent            bool                `gorm:"default:false" json:"skip_consent"`
	SubjectType            string              `gorm:"default:'public'" json:"subject_type"`
	BackchannelLogoutURI   string              `gorm:"type:text" json:"backchannel_logout_uri"`

	// --- Lifespans ---
	AccessTokenLifespan  string `gorm:"default:''" json:"access_token_lifespan,omitempty"`
	RefreshTokenLifespan string `gorm:"default:''" json:"refresh_token_lifespan,omitempty"`
	IDTokenLifespan      string `gorm:"default:''" json:"id_token_lifespan,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
