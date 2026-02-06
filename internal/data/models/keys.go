package models

import (
	"time"
)

// SigningKey stores the encrypted RSA private key in the database.
type SigningKey struct {
	ID        string `gorm:"primaryKey"`         // e.g. "shyntr-key-1"
	Algorithm string `gorm:"not null"`           // e.g. "RS256"
	KeyData   string `gorm:"type:text;not null"` // Encrypted Private Key (Base64)
	Active    bool   `gorm:"default:true"`
	CreatedAt time.Time
	UpdatedAt time.Time
}
