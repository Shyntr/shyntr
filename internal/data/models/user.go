package models

import (
	"time"

	"gorm.io/gorm"
)

// User represents the identity of a person in Shyntr.
type User struct {
	ID           string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Email        string `gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null"`

	FirstName   string
	LastName    string
	PhoneNumber string
	Address     string
	BirthDate   time.Time

	IsActive bool   `gorm:"default:true"`
	Role     string `gorm:"default:'user'"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}
