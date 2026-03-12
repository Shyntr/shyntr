package dto

import "github.com/Shyntr/shyntr/internal/domain/entity"

type CreateTenantRequest struct {
	ID          string `json:"id"`
	Name        string `json:"name" binding:"required"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
}

type TenantResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	IssuerURL   string `json:"issuer_url,omitempty"`
}

func (req *CreateTenantRequest) ToDomain() *entity.Tenant {
	return &entity.Tenant{
		ID:          req.ID,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
	}
}

func FromDomainTenant(t *entity.Tenant) *TenantResponse {
	return &TenantResponse{
		ID:          t.ID,
		Name:        t.Name,
		DisplayName: t.DisplayName,
		Description: t.Description,
		IssuerURL:   t.IssuerURL,
	}
}

func FromDomainTenants(tenants []*entity.Tenant) []*TenantResponse {
	responses := make([]*TenantResponse, 0, len(tenants))

	for _, t := range tenants {
		responses = append(responses, FromDomainTenant(t))
	}

	return responses
}
