package models

import (
	"time"
)

// BlacklistedJTI stores JWT IDs that have already been used for Client Authentication.
// This prevents Replay Attacks (RFC 7523).
type BlacklistedJTI struct {
	JTI       string    `gorm:"primaryKey"`
	ExpiresAt time.Time `gorm:"index"`
}
