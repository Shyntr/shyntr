package entity

import "time"

type SAMLReplayCache struct {
	MessageID string
	TenantID  string
	ExpiresAt time.Time
	CreatedAt time.Time
}
