package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Tenant represents an isolated environment within Shyntr.
// Each tenant has its own Configuration and Clients.
type Tenant struct {
	ID   string `gorm:"primaryKey" json:"id"`
	Name string `gorm:"uniqueIndex;not null" json:"name"`

	DisplayName string `gorm:"default:''" json:"display_name"`
	Description string `gorm:"default:''" json:"description"`

	IssuerURL string `json:"issuer_url"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (t *Tenant) BeforeCreate(tx *gorm.DB) (err error) {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	return
}
