package models

import (
	"github.com/lib/pq"
	"time"
)

// OAuth2Client represents a registered application allowed to use Shyntr.
type OAuth2Client struct {
	ID            string         `gorm:"primaryKey"`
	Secret        string         `gorm:"not null"`
	RedirectURIs  pq.StringArray `gorm:"type:text[]"`
	GrantTypes    pq.StringArray `gorm:"type:text[]"`
	ResponseTypes pq.StringArray `gorm:"type:text[]"`
	Scopes        pq.StringArray `gorm:"type:text[]"`
	Public        bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
