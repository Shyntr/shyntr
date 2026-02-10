package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents the identity of a person within a specific Tenant.
type User struct {
	ID string `gorm:"primaryKey"`

	TenantID string `gorm:"index;uniqueIndex:idx_email_tenant;not null"`

	Email string `gorm:"uniqueIndex:idx_email_tenant;not null"`

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

func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	return
}
