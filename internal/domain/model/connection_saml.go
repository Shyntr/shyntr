package model

import (
	"errors"
	"time"
)

type SAMLConnection struct {
	ID                       string                          `json:"id"`
	TenantID                 string                          `json:"tenant_id"`
	Name                     string                          `json:"name"`
	IdpMetadataXML           string                          `json:"idp_metadata_xml"`
	IdpEntityID              string                          `json:"idp_entity_id"`
	IdpSingleSignOn          string                          `json:"idp_single_sign_on"`
	IdpSloUrl                string                          `json:"idp_slo_url"`
	IdpCertificate           string                          `json:"idp_certificate"`
	IdpEncryptionCertificate string                          `json:"idp_encryption_certificate"`
	MetadataURL              string                          `json:"metadata_url"`
	SPPrivateKey             string                          `json:"sp_private_key"`
	AttributeMapping         map[string]AttributeMappingRule `json:"attribute_mapping"`
	ForceAuthn               bool                            `json:"force_authn"`
	SignRequest              bool                            `json:"sign_request"`
	Active                   bool                            `json:"active"`
	SPCertificate            string                          `json:"-"`
	RequestedContexts        []string                        `json:"-"`
	CreatedAt                time.Time                       `json:"created_at"`
	UpdatedAt                time.Time                       `json:"updated_at,omitempty"`
}

func (c *SAMLConnection) Validate() error {
	if c.TenantID == "" {
		return errors.New("tenant_id is required")
	}
	if c.IdpEntityID == "" {
		return errors.New("idp_entity_id is required")
	}
	if c.IdpSingleSignOn == "" {
		return errors.New("idp_sso_url is required")
	}
	if c.IdpCertificate == "" {
		return errors.New("idp_certificate is required")
	}
	return nil
}
