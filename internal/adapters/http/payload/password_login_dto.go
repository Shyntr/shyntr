package payload

import (
	"time"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

// ----- Endpoint request/response DTOs -----

type CreatePasswordLoginEndpointRequest struct {
	Name     string `json:"name" binding:"required"`
	LoginURL string `json:"login_url" binding:"required"`
	IsActive *bool  `json:"is_active"`
}

type UpdatePasswordLoginEndpointRequest struct {
	Name     string `json:"name" binding:"required"`
	LoginURL string `json:"login_url" binding:"required"`
	IsActive *bool  `json:"is_active"`
}

type PasswordLoginEndpointResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	LoginURL  string    `json:"login_url"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func FromDomainPasswordLoginEndpoint(e *model.PasswordLoginEndpoint) *PasswordLoginEndpointResponse {
	return &PasswordLoginEndpointResponse{
		ID:        e.ID,
		Name:      e.Name,
		LoginURL:  e.LoginURL,
		IsActive:  e.IsActive,
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
	}
}

func FromDomainPasswordLoginEndpoints(items []*model.PasswordLoginEndpoint) []*PasswordLoginEndpointResponse {
	out := make([]*PasswordLoginEndpointResponse, 0, len(items))
	for _, e := range items {
		out = append(out, FromDomainPasswordLoginEndpoint(e))
	}
	return out
}

// ----- Assignment request/response DTOs -----

type CreatePasswordLoginAssignmentRequest struct {
	TenantID                *string `json:"tenant_id"`
	PasswordLoginEndpointID string  `json:"password_login_endpoint_id" binding:"required"`
	Enabled                 *bool   `json:"enabled"`
}

type UpdatePasswordLoginAssignmentRequest struct {
	PasswordLoginEndpointID string `json:"password_login_endpoint_id" binding:"required"`
	Enabled                 *bool  `json:"enabled"`
}

type PasswordLoginAssignmentResponse struct {
	ID                      string    `json:"id"`
	TenantID                *string   `json:"tenant_id"`
	PasswordLoginEndpointID string    `json:"password_login_endpoint_id"`
	Enabled                 bool      `json:"enabled"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

func FromDomainPasswordLoginAssignment(a *model.PasswordLoginAssignment) *PasswordLoginAssignmentResponse {
	return &PasswordLoginAssignmentResponse{
		ID:                      a.ID,
		TenantID:                a.TenantID,
		PasswordLoginEndpointID: a.PasswordLoginEndpointID,
		Enabled:                 a.Enabled,
		CreatedAt:               a.CreatedAt,
		UpdatedAt:               a.UpdatedAt,
	}
}

func FromDomainPasswordLoginAssignments(items []*model.PasswordLoginAssignment) []*PasswordLoginAssignmentResponse {
	out := make([]*PasswordLoginAssignmentResponse, 0, len(items))
	for _, a := range items {
		out = append(out, FromDomainPasswordLoginAssignment(a))
	}
	return out
}
