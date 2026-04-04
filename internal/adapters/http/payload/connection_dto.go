package payload

import (
	"strings"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

func normalizeURL(value string) string { return strings.TrimRight(strings.TrimSpace(value), "/") }

type CreateOIDCConnectionRequest struct {
	ID                    string                                `json:"id" example:"conn_oidc_123"`
	TenantID              string                                `json:"tenant_id" binding:"required" example:"tnt_alpha01"`
	Name                  string                                `json:"name" binding:"required" example:"Google Workspace SSO"`
	IssuerURL             string                                `json:"issuer_url" binding:"required" example:"https://accounts.google.com"`
	ClientID              string                                `json:"client_id" binding:"required" example:"google-client-id.apps.googleusercontent.com"`
	ClientSecret          string                                `json:"client_secret" example:"YOUR_SECURE_CLIENT_SECRET"`
	Scopes                []string                              `json:"scopes" binding:"required" example:"openid,profile,email"`
	AttributeMapping      map[string]model.AttributeMappingRule `json:"attribute_mapping" swaggertype:"object"`
	AuthorizationEndpoint string                                `json:"authorization_endpoint" example:"https://accounts.google.com/o/oauth2/v2/auth"`
	EndSessionEndpoint    string                                `json:"end_session_endpoint" example:"https://oauth2.googleapis.com/revoke"`
	TokenEndpoint         string                                `json:"token_endpoint" example:"https://oauth2.googleapis.com/token"`
	UserInfoEndpoint      string                                `json:"user_info_endpoint" example:"https://openidconnect.googleapis.com/v1/userinfo"`
	JWKSURI               string                                `json:"jwks_uri" example:"https://www.googleapis.com/oauth2/v3/certs"`
}

type OIDCConnectionResponse struct {
	ID                    string                                `json:"id" example:"conn_oidc_123"`
	TenantID              string                                `json:"tenant_id" example:"tnt_alpha01"`
	Name                  string                                `json:"name" example:"Google Workspace SSO"`
	IssuerURL             string                                `json:"issuer_url" example:"https://accounts.google.com"`
	ClientID              string                                `json:"client_id" example:"google-client-id.apps.googleusercontent.com"`
	ClientSecret          string                                `json:"client_secret" example:"*****"`
	Scopes                []string                              `json:"scopes" example:"openid,profile,email"`
	AttributeMapping      map[string]model.AttributeMappingRule `json:"attribute_mapping" swaggertype:"object"`
	AuthorizationEndpoint string                                `json:"authorization_endpoint"`
	EndSessionEndpoint    string                                `json:"end_session_endpoint"`
	TokenEndpoint         string                                `json:"token_endpoint"`
	UserInfoEndpoint      string                                `json:"user_info_endpoint"`
	JWKSURI               string                                `json:"jwks_uri"`
	Active                bool                                  `json:"active" example:"true"`
	CreatedAt             string                                `json:"created_at" example:"2026-03-14T12:00:00Z"`
	UpdatedAt             string                                `json:"updated_at,omitempty"`
}

type CreateSAMLConnectionRequest struct {
	ID                       string                                `json:"id" example:"conn_saml_123"`
	TenantID                 string                                `json:"tenant_id" binding:"required" example:"tnt_alpha01"`
	Name                     string                                `json:"name" binding:"required" example:"Corporate Okta SSO"`
	IdpMetadataXML           string                                `json:"idp_metadata_xml" example:"<md:EntityDescriptor>...</md:EntityDescriptor>"`
	IdpEntityID              string                                `json:"idp_entity_id" example:"http://www.okta.com/exk12345"`
	IdpSingleSignOn          string                                `json:"idp_single_sign_on" example:"https://corp.okta.com/app/shyntr/exk12345/sso/saml"`
	IdpSloUrl                string                                `json:"idp_slo_url" example:"https://corp.okta.com/app/shyntr/exk12345/slo/saml"`
	MetadataURL              string                                `json:"metadata_url" example:"https://corp.okta.com/app/shyntr/exk12345/sso/saml/metadata"`
	IdpCertificate           string                                `json:"idp_certificate" example:"MIID...[Base64_Cert]...=="`
	IdpEncryptionCertificate string                                `json:"idp_encryption_certificate"`
	SPPrivateKey             string                                `json:"sp_private_key" example:"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"`
	AttributeMapping         map[string]model.AttributeMappingRule `json:"attribute_mapping" swaggertype:"object"`
	ForceAuthn               bool                                  `json:"force_authn" example:"false"`
	SignRequest              bool                                  `json:"sign_request" example:"true"`
}

type SAMLConnectionResponse struct {
	ID                       string                                `json:"id" example:"conn_saml_123"`
	TenantID                 string                                `json:"tenant_id" example:"tnt_alpha01"`
	Name                     string                                `json:"name" example:"Corporate Okta SSO"`
	IdpMetadataXML           string                                `json:"idp_metadata_xml"`
	IdpEntityID              string                                `json:"idp_entity_id" example:"http://www.okta.com/exk12345"`
	IdpSingleSignOn          string                                `json:"idp_single_sign_on" example:"https://corp.okta.com/app/shyntr/exk12345/sso/saml"`
	IdpSloUrl                string                                `json:"idp_slo_url"`
	MetadataURL              string                                `json:"metadata_url"`
	IdpCertificate           string                                `json:"idp_certificate"`
	IdpEncryptionCertificate string                                `json:"idp_encryption_certificate"`
	SPPrivateKey             string                                `json:"sp_private_key" example:"*****"`
	AttributeMapping         map[string]model.AttributeMappingRule `json:"attribute_mapping" swaggertype:"object"`
	ForceAuthn               bool                                  `json:"force_authn" example:"false"`
	SignRequest              bool                                  `json:"sign_request" example:"true"`
	Active                   bool                                  `json:"active" example:"true"`
	CreatedAt                string                                `json:"created_at" example:"2026-03-14T12:00:00Z"`
	UpdatedAt                string                                `json:"updated_at,omitempty"`
}

func (req *CreateOIDCConnectionRequest) ToDomain() *model.OIDCConnection {
	return &model.OIDCConnection{
		ID:                    req.ID,
		TenantID:              req.TenantID,
		Name:                  req.Name,
		IssuerURL:             normalizeURL(req.IssuerURL),
		ClientID:              req.ClientID,
		ClientSecret:          req.ClientSecret,
		Scopes:                req.Scopes,
		AttributeMapping:      req.AttributeMapping,
		AuthorizationEndpoint: normalizeURL(req.AuthorizationEndpoint),
		EndSessionEndpoint:    normalizeURL(req.EndSessionEndpoint),
		TokenEndpoint:         normalizeURL(req.TokenEndpoint),
		UserInfoEndpoint:      normalizeURL(req.UserInfoEndpoint),
		JWKSURI:               normalizeURL(req.JWKSURI),
	}
}

func FromDomainOIDCConnection(c *model.OIDCConnection) *OIDCConnectionResponse {
	return &OIDCConnectionResponse{
		ID:                    c.ID,
		TenantID:              c.TenantID,
		Name:                  c.Name,
		IssuerURL:             c.IssuerURL,
		ClientID:              c.ClientID,
		ClientSecret:          c.ClientSecret,
		Scopes:                c.Scopes,
		AttributeMapping:      c.AttributeMapping,
		AuthorizationEndpoint: c.AuthorizationEndpoint,
		EndSessionEndpoint:    c.EndSessionEndpoint,
		TokenEndpoint:         c.TokenEndpoint,
		UserInfoEndpoint:      c.UserInfoEndpoint,
		JWKSURI:               c.JWKSURI,
		Active:                c.Active,
		CreatedAt:             c.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:             c.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

func (req *CreateSAMLConnectionRequest) ToDomain() *model.SAMLConnection {
	return &model.SAMLConnection{
		ID:                       req.ID,
		TenantID:                 req.TenantID,
		Name:                     req.Name,
		IdpMetadataXML:           req.IdpMetadataXML,
		IdpEntityID:              req.IdpEntityID,
		IdpSingleSignOn:          normalizeURL(req.IdpSingleSignOn),
		IdpSloUrl:                normalizeURL(req.IdpSloUrl),
		MetadataURL:              normalizeURL(req.MetadataURL),
		IdpCertificate:           req.IdpCertificate,
		IdpEncryptionCertificate: req.IdpEncryptionCertificate,
		SPPrivateKey:             req.SPPrivateKey,
		AttributeMapping:         req.AttributeMapping,
		ForceAuthn:               req.ForceAuthn,
		SignRequest:              req.SignRequest,
	}
}

func FromDomainSAMLConnection(c *model.SAMLConnection) *SAMLConnectionResponse {
	return &SAMLConnectionResponse{
		ID:                       c.ID,
		TenantID:                 c.TenantID,
		Name:                     c.Name,
		IdpMetadataXML:           c.IdpMetadataXML,
		IdpEntityID:              c.IdpEntityID,
		IdpSingleSignOn:          c.IdpSingleSignOn,
		IdpSloUrl:                c.IdpSloUrl,
		MetadataURL:              c.MetadataURL,
		IdpCertificate:           c.IdpCertificate,
		IdpEncryptionCertificate: c.IdpEncryptionCertificate,
		SPPrivateKey:             c.SPPrivateKey,
		AttributeMapping:         c.AttributeMapping,
		ForceAuthn:               c.ForceAuthn,
		SignRequest:              c.SignRequest,
		Active:                   c.Active,
		CreatedAt:                c.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:                c.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}
