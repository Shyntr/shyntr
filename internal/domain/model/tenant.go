package model

import (
	"errors"
	"time"
)

type Tenant struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	Description string    `json:"description"`
	IssuerURL   string    `json:"issuer_url,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

func (t *Tenant) Validate() error {
	if t.Name == "" {
		return errors.New("tenant name cannot be empty")
	}
	return nil
}
