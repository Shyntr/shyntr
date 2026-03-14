package model

import (
	"errors"
	"time"
)

type SAMLClient struct {
	ID                      string                          `json:"id"`
	TenantID                string                          `json:"tenant_id"`
	Name                    string                          `json:"name"`
	EntityID                string                          `json:"entity_id"`
	ACSURL                  string                          `json:"acs_url"`
	SLOURL                  string                          `json:"slo_url"`
	SPCertificate           string                          `json:"-"`
	SPEncryptionCertificate string                          `json:"-"`
	MetadataURL             string                          `json:"metadata_url"`
	AttributeMapping        map[string]AttributeMappingRule `json:"attribute_mapping"`
	AllowedScopes           []string                        `json:"allowed_scopes"`
	ForceAuthn              bool                            `json:"force_authn"`
	SignResponse            bool                            `json:"sign_response"`
	SignAssertion           bool                            `json:"sign_assertion"`
	EncryptAssertion        bool                            `json:"encrypt_assertion"`
	Active                  bool                            `json:"active"`
	CreatedAt               time.Time                       `json:"created_at"`
	UpdatedAt               time.Time                       `json:"updated_at,omitempty"`
}

func (c *SAMLClient) Validate() error {
	if c.TenantID == "" {
		return errors.New("tenant_id is required")
	}
	if c.EntityID == "" {
		return errors.New("entity_id is required")
	}
	if c.ACSURL == "" {
		return errors.New("acs_url is required")
	}
	return nil
}
