package entity

import "time"

type LoginRequest struct {
	ID                string
	TenantID          string
	ClientID          string
	Subject           string
	RequestedScope    []string
	RequestedAudience []string
	RequestURL        string
	Protocol          string
	SAMLRequestID     string
	ClientIP          string
	Context           []byte // JSON encoded state
	Authenticated     bool
	Remember          bool
	RememberFor       int
	Active            bool
	Skip              bool
	SessionID         string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type ConsentRequest struct {
	ID                string
	LoginChallenge    string
	ClientID          string
	Subject           string
	RequestedScope    []string
	RequestedAudience []string
	GrantedScope      []string
	GrantedAudience   []string
	RequestURL        string
	Context           []byte // JSON encoded session
	Skip              bool
	Authenticated     bool
	Remember          bool
	RememberFor       int
	Active            bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}
