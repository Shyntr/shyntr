package dto

import (
	"time"

	"github.com/nevzatcirak/shyntr/internal/domain/entity"
)

type CreateSAMLClientRequest struct {
	TenantID                string                                 `json:"tenant_id"`
	Name                    string                                 `json:"name"`
	EntityID                string                                 `json:"entity_id"`
	ACSURL                  string                                 `json:"acs_url"`
	SLOURL                  string                                 `json:"slo_url"`
	SPCertificate           string                                 `json:"sp_certificate"`
	SPEncryptionCertificate string                                 `json:"sp_encryption_certificate"`
	MetadataURL             string                                 `json:"metadata_url"`
	AttributeMapping        map[string]entity.AttributeMappingRule `json:"attribute_mapping"`
	ForceAuthn              bool                                   `json:"force_authn"`
	SignResponse            bool                                   `json:"sign_response"`
	SignAssertion           bool                                   `json:"sign_assertion"`
	EncryptAssertion        bool                                   `json:"encrypt_assertion"`
}

type SAMLClientResponse struct {
	ID                      string                                 `json:"id"`
	TenantID                string                                 `json:"tenant_id"`
	Name                    string                                 `json:"name"`
	EntityID                string                                 `json:"entity_id"`
	ACSURL                  string                                 `json:"acs_url"`
	SLOURL                  string                                 `json:"slo_url"`
	SPCertificate           string                                 `json:"sp_certificate"`
	SPEncryptionCertificate string                                 `json:"sp_encryption_certificate"`
	MetadataURL             string                                 `json:"metadata_url"`
	AttributeMapping        map[string]entity.AttributeMappingRule `json:"attribute_mapping"`
	ForceAuthn              bool                                   `json:"force_authn"`
	SignResponse            bool                                   `json:"sign_response"`
	SignAssertion           bool                                   `json:"sign_assertion"`
	EncryptAssertion        bool                                   `json:"encrypt_assertion"`
	Active                  bool                                   `json:"active"`
	CreatedAt               time.Time                              `json:"created_at"`
	UpdatedAt               time.Time                              `json:"updated_at,omitempty"`
}

func (req *CreateSAMLClientRequest) ToDomain() *entity.SAMLClient {
	return &entity.SAMLClient{
		TenantID:                req.TenantID,
		Name:                    req.Name,
		EntityID:                req.EntityID,
		ACSURL:                  req.ACSURL,
		SLOURL:                  req.SLOURL,
		SPCertificate:           req.SPCertificate,
		SPEncryptionCertificate: req.SPEncryptionCertificate,
		MetadataURL:             req.MetadataURL,
		AttributeMapping:        req.AttributeMapping,
		ForceAuthn:              req.ForceAuthn,
		SignResponse:            req.SignResponse,
		SignAssertion:           req.SignAssertion,
		EncryptAssertion:        req.EncryptAssertion,
	}
}

func FromDomainSAMLClient(c *entity.SAMLClient) *SAMLClientResponse {
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
		ForceAuthn:              c.ForceAuthn,
		SignResponse:            c.SignResponse,
		SignAssertion:           c.SignAssertion,
		EncryptAssertion:        c.EncryptAssertion,
		Active:                  c.Active,
		CreatedAt:               c.CreatedAt,
		UpdatedAt:               c.UpdatedAt,
	}
}

func FromDomainSAMLClients(clients []*entity.SAMLClient) []*SAMLClientResponse {
	responses := make([]*SAMLClientResponse, 0, len(clients))

	for i := range clients {
		responses = append(responses, FromDomainSAMLClient(clients[i]))
	}

	return responses
}
