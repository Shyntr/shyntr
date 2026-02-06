package models

import (
	"gorm.io/gorm"
	"time"
)

// User represents the identity of a person in Shyntr.
type User struct {
	ID           string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Email        string `gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null"`
	FirstName    string
	LastName     string
	IsActive     bool   `gorm:"default:true"`
	Role         string `gorm:"default:'user'"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"index"`
}
