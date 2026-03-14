package model

import (
	"errors"
	"time"
)

type Scope struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Claims      []string  `json:"claims"`
	IsSystem    bool      `json:"is_system"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

func (s *Scope) Validate() error {
	if s.TenantID == "" {
		return errors.New("tenant_id is required")
	}
	if s.Name == "" {
		return errors.New("scope name is required")
	}
	return nil
}
