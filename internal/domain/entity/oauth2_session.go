package entity

import (
	"time"

	"github.com/lib/pq"
	"gorm.io/gorm"
)

// OAuth2Session stores the session data for OAuth2 tokens.
type OAuth2Session struct {
	Signature       string // The token signature
	Type            string // access_token, refresh_token, code, pkce, oidc
	RequestID       string
	ClientID        string
	Subject         string
	TokenFamilyID   string
	Active          bool
	GrantedScopes   pq.StringArray
	RequestData     []byte
	SessionData     []byte
	ExpiresAt       time.Time
	GraceExpiresAt  *time.Time
	GraceUsedAt     *time.Time
	ReuseDetectedAt *time.Time
	UsedAt          *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       gorm.DeletedAt
}
