package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Tenant represents an isolated environment within Shyntr.
// Each tenant has its own Users, Clients, and Configuration.
type Tenant struct {
	ID        string `gorm:"primaryKey"` // e.g., "default", "customer-a"
	Name      string `gorm:"not null"`
	IssuerURL string

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (t *Tenant) BeforeCreate(tx *gorm.DB) (err error) {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	return
}
