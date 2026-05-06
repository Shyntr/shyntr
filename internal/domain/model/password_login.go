package model

import "time"

// PasswordLoginEndpoint is a reusable password verifier endpoint definition.
// It defines a remote URL that handles username/password verification for tenants.
// login_url must always be an absolute http or https URL.
type PasswordLoginEndpoint struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	LoginURL  string    `json:"login_url"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PasswordLoginAssignment assigns a PasswordLoginEndpoint to a tenant.
// When TenantID is nil, the assignment is global and applies to all tenants
// that have no tenant-specific active assignment.
// Tenant-specific assignments always take precedence over global ones.
type PasswordLoginAssignment struct {
	ID                      string    `json:"id"`
	TenantID                *string   `json:"tenant_id"` // nil = global assignment
	PasswordLoginEndpointID string    `json:"password_login_endpoint_id"`
	Enabled                 bool      `json:"enabled"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}
