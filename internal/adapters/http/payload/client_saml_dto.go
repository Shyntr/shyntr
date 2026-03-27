package payload

import (
	"time"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

type CreateSAMLClientRequest struct {
	TenantID                string                                `json:"tenant_id" example:"tnt_alpha01"`
	Name                    string                                `json:"name" example:"Acme Corp Finance App"`
	EntityID                string                                `json:"entity_id" example:"https://finance.acme.corp/saml/metadata"`
	ACSURL                  string                                `json:"acs_url" example:"https://finance.acme.corp/saml/acs"`
	SLOURL                  string                                `json:"slo_url" example:"https://finance.acme.corp/saml/slo"`
	SPCertificate           string                                `json:"sp_certificate" example:"MIID...[Base64_Cert]...=="`
	SPEncryptionCertificate string                                `json:"sp_encryption_certificate" example:"MIID...[Base64_Cert]...=="`
	MetadataURL             string                                `json:"metadata_url" example:"https://finance.acme.corp/saml/metadata.xml"`
	AttributeMapping        map[string]model.AttributeMappingRule `json:"attribute_mapping" swaggertype:"object"`
	AllowedScopes           []string                              `json:"allowed_scopes" example:"email,profile,groups"`
	ForceAuthn              bool                                  `json:"force_authn" example:"true"`
	SignResponse            bool                                  `json:"sign_response" example:"true"`
	SignAssertion           bool                                  `json:"sign_assertion" example:"true"`
	EncryptAssertion        bool                                  `json:"encrypt_assertion" example:"false"`
}

type SAMLClientResponse struct {
	ID                      string                                `json:"id" example:"cli_saml_12345"`
	TenantID                string                                `json:"tenant_id" example:"tnt_alpha01"`
	Name                    string                                `json:"name" example:"Acme Corp Finance App"`
	EntityID                string                                `json:"entity_id" example:"https://finance.acme.corp/saml/metadata"`
	ACSURL                  string                                `json:"acs_url" example:"https://finance.acme.corp/saml/acs"`
	SLOURL                  string                                `json:"slo_url" example:"https://finance.acme.corp/saml/slo"`
	SPCertificate           string                                `json:"sp_certificate"`
	SPEncryptionCertificate string                                `json:"sp_encryption_certificate"`
	MetadataURL             string                                `json:"metadata_url" example:"https://finance.acme.corp/saml/metadata.xml"`
	AttributeMapping        map[string]model.AttributeMappingRule `json:"attribute_mapping" swaggertype:"object"`
	AllowedScopes           []string                              `json:"allowed_scopes" example:"email,profile,groups"`
	ForceAuthn              bool                                  `json:"force_authn" example:"true"`
	SignResponse            bool                                  `json:"sign_response" example:"true"`
	SignAssertion           bool                                  `json:"sign_assertion" example:"true"`
	EncryptAssertion        bool                                  `json:"encrypt_assertion" example:"false"`
	Active                  bool                                  `json:"active" example:"true"`
	CreatedAt               time.Time                             `json:"created_at"`
	UpdatedAt               time.Time                             `json:"updated_at,omitempty"`
}

func (req *CreateSAMLClientRequest) ToDomain() *model.SAMLClient {
	return &model.SAMLClient{
		TenantID:                req.TenantID,
		Name:                    req.Name,
		EntityID:                req.EntityID,
		ACSURL:                  req.ACSURL,
		SLOURL:                  req.SLOURL,
		SPCertificate:           req.SPCertificate,
		SPEncryptionCertificate: req.SPEncryptionCertificate,
		MetadataURL:             req.MetadataURL,
		AttributeMapping:        req.AttributeMapping,
		AllowedScopes:           req.AllowedScopes,
		ForceAuthn:              req.ForceAuthn,
		SignResponse:            req.SignResponse,
		SignAssertion:           req.SignAssertion,
		EncryptAssertion:        req.EncryptAssertion,
	}
}

func FromDomainSAMLClient(c *model.SAMLClient) *SAMLClientResponse {
	return &SAMLClientResponse{
		ID:                      c.ID,
		TenantID:                c.TenantID,
		Name:                    c.Name,
		EntityID:                c.EntityID,
		ACSURL:                  c.ACSURL,
		SLOURL:                  c.SLOURL,
		SPCertificate:           c.SPCertificate,
		SPEncryptionCertificate: c.SPEncryptionCertificate,
		MetadataURL:             c.MetadataURL,
		AttributeMapping:        c.AttributeMapping,
		AllowedScopes:           c.AllowedScopes,
		ForceAuthn:              c.ForceAuthn,
		SignResponse:            c.SignResponse,
		SignAssertion:           c.SignAssertion,
		EncryptAssertion:        c.EncryptAssertion,
		Active:                  c.Active,
		CreatedAt:               c.CreatedAt,
		UpdatedAt:               c.UpdatedAt,
	}
}

func FromDomainSAMLClients(clients []*model.SAMLClient) []*SAMLClientResponse {
	responses := make([]*SAMLClientResponse, 0, len(clients))

	for i := range clients {
		responses = append(responses, FromDomainSAMLClient(clients[i]))
	}

	return responses
}
