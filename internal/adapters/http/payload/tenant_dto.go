package payload

import "github.com/Shyntr/shyntr/internal/domain/model"

type CreateTenantRequest struct {
	ID          string `json:"id" example:"tnt_alpha01"`
	Name        string `json:"name" binding:"required" example:"alpha-production"`
	DisplayName string `json:"display_name" example:"Alpha Corp Production"`
	Description string `json:"description" example:"Main production environment for Alpha Corp"`
}

type TenantResponse struct {
	ID          string `json:"id" example:"tnt_alpha01"`
	Name        string `json:"name" example:"alpha-production"`
	DisplayName string `json:"display_name" example:"Alpha Corp Production"`
	Description string `json:"description" example:"Main production environment for Alpha Corp"`
	IssuerURL   string `json:"issuer_url,omitempty" example:"https://api.shyntr.internal/t/tnt_alpha01"`
}

func (req *CreateTenantRequest) ToDomain() *model.Tenant {
	return &model.Tenant{
		ID:          req.ID,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
	}
}

func FromDomainTenant(t *model.Tenant) *TenantResponse {
	return &TenantResponse{
		ID:          t.ID,
		Name:        t.Name,
		DisplayName: t.DisplayName,
		Description: t.Description,
		IssuerURL:   t.IssuerURL,
	}
}

func FromDomainTenants(tenants []*model.Tenant) []*TenantResponse {
	responses := make([]*TenantResponse, 0, len(tenants))

	for _, t := range tenants {
		responses = append(responses, FromDomainTenant(t))
	}

	return responses
}
