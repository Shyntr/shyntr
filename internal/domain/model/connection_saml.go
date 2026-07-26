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
	SPPrivateKey             string                          `json:"-"`
	AttributeMapping         map[string]AttributeMappingRule `json:"attribute_mapping"`
	AttributePassthrough     bool                            `json:"attribute_passthrough"`
	AttributeExclude         []string                        `json:"attribute_exclude"`
	NameIDFormat             string                          `json:"name_id_format,omitempty"`
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
	for _, rule := range c.AttributeMapping {
		if rule.NameFormat != "" && !IsValidAttributeNameFormat(rule.NameFormat) {
			return errors.New("attribute mapping name_format must be a SAML 2.0 attrname-format (uri, basic, or unspecified)")
		}
	}
	if c.NameIDFormat != "" && !IsValidNameIDFormat(c.NameIDFormat) {
		return errors.New("name_id_format must be a supported SAML 2.0 nameid-format (unspecified, emailAddress, or transient)")
	}
	return nil
}
