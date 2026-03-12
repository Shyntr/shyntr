package dto

import (
	"github.com/Shyntr/shyntr/internal/domain/entity"
)

type CreateOIDCConnectionRequest struct {
	ID                    string                                 `json:"id"`
	TenantID              string                                 `json:"tenant_id" binding:"required"`
	Name                  string                                 `json:"name" binding:"required"`
	IssuerURL             string                                 `json:"issuer_url" binding:"required"`
	ClientID              string                                 `json:"client_id" binding:"required"`
	ClientSecret          string                                 `json:"client_secret"`
	Scopes                []string                               `json:"scopes" binding:"required"`
	AttributeMapping      map[string]entity.AttributeMappingRule `json:"attribute_mapping"`
	AuthorizationEndpoint string                                 `json:"authorization_endpoint"`
	EndSessionEndpoint    string                                 `json:"end_session_endpoint"`
	TokenEndpoint         string                                 `json:"token_endpoint"`
	UserInfoEndpoint      string                                 `json:"user_info_endpoint"`
	JWKSURI               string                                 `json:"jwks_uri"`
}

type OIDCConnectionResponse struct {
	ID                    string                                 `json:"id"`
	TenantID              string                                 `json:"tenant_id"`
	Name                  string                                 `json:"name"`
	IssuerURL             string                                 `json:"issuer_url"`
	ClientID              string                                 `json:"client_id"`
	ClientSecret          string                                 `json:"client_secret"`
	Scopes                []string                               `json:"scopes"`
	AttributeMapping      map[string]entity.AttributeMappingRule `json:"attribute_mapping"`
	AuthorizationEndpoint string                                 `json:"authorization_endpoint"`
	EndSessionEndpoint    string                                 `json:"end_session_endpoint"`
	TokenEndpoint         string                                 `json:"token_endpoint"`
	UserInfoEndpoint      string                                 `json:"user_info_endpoint"`
	JWKSURI               string                                 `json:"jwks_uri"`
	Active                bool                                   `json:"active"`
	CreatedAt             string                                 `json:"created_at"`
	UpdatedAt             string                                 `json:"updated_at,omitempty"`
}

type CreateSAMLConnectionRequest struct {
	ID                       string                                 `json:"id"`
	TenantID                 string                                 `json:"tenant_id" binding:"required"`
	Name                     string                                 `json:"name" binding:"required"`
	IdpMetadataXML           string                                 `json:"idp_metadata_xml"`
	IdpEntityID              string                                 `json:"idp_entity_id"`
	IdpSingleSignOn          string                                 `json:"idp_single_sign_on"`
	IdpSloUrl                string                                 `json:"idp_slo_url"`
	MetadataURL              string                                 `json:"metadata_url"`
	IdpCertificate           string                                 `json:"idp_certificate"`
	IdpEncryptionCertificate string                                 `json:"idp_encryption_certificate"`
	SPPrivateKey             string                                 `json:"sp_private_key"`
	AttributeMapping         map[string]entity.AttributeMappingRule `json:"attribute_mapping"`
	ForceAuthn               bool                                   `json:"force_authn"`
	SignRequest              bool                                   `json:"sign_request"`
}

type SAMLConnectionResponse struct {
	ID                       string                                 `json:"id"`
	TenantID                 string                                 `json:"tenant_id"`
	Name                     string                                 `json:"name"`
	IdpMetadataXML           string                                 `json:"idp_metadata_xml"`
	IdpEntityID              string                                 `json:"idp_entity_id"`
	IdpSingleSignOn          string                                 `json:"idp_single_sign_on"`
	IdpSloUrl                string                                 `json:"idp_slo_url"`
	MetadataURL              string                                 `json:"metadata_url"`
	IdpCertificate           string                                 `json:"idp_certificate"`
	IdpEncryptionCertificate string                                 `json:"idp_encryption_certificate"`
	SPPrivateKey             string                                 `json:"sp_private_key"`
	AttributeMapping         map[string]entity.AttributeMappingRule `json:"attribute_mapping"`
	ForceAuthn               bool                                   `json:"force_authn"`
	SignRequest              bool                                   `json:"sign_request"`
	Active                   bool                                   `json:"active"`
	CreatedAt                string                                 `json:"created_at"`
	UpdatedAt                string                                 `json:"updated_at,omitempty"`
}

func (req *CreateOIDCConnectionRequest) ToDomain() *entity.OIDCConnection {
	return &entity.OIDCConnection{
		ID:                    req.ID,
		TenantID:              req.TenantID,
		Name:                  req.Name,
		IssuerURL:             req.IssuerURL,
		ClientID:              req.ClientID,
		ClientSecret:          req.ClientSecret,
		Scopes:                req.Scopes,
		AttributeMapping:      req.AttributeMapping,
		AuthorizationEndpoint: req.AuthorizationEndpoint,
		EndSessionEndpoint:    req.EndSessionEndpoint,
		TokenEndpoint:         req.TokenEndpoint,
		UserInfoEndpoint:      req.UserInfoEndpoint,
		JWKSURI:               req.JWKSURI,
	}
}

func FromDomainOIDCConnection(c *entity.OIDCConnection) *OIDCConnectionResponse {
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

func (req *CreateSAMLConnectionRequest) ToDomain() *entity.SAMLConnection {
	return &entity.SAMLConnection{
		ID:                       req.ID,
		TenantID:                 req.TenantID,
		Name:                     req.Name,
		IdpMetadataXML:           req.IdpMetadataXML,
		IdpEntityID:              req.IdpEntityID,
		IdpSingleSignOn:          req.IdpSingleSignOn,
		IdpSloUrl:                req.IdpSloUrl,
		MetadataURL:              req.MetadataURL,
		IdpCertificate:           req.IdpCertificate,
		IdpEncryptionCertificate: req.IdpEncryptionCertificate,
		SPPrivateKey:             req.SPPrivateKey,
		AttributeMapping:         req.AttributeMapping,
		ForceAuthn:               req.ForceAuthn,
		SignRequest:              req.SignRequest,
	}
}

func FromDomainSAMLConnection(c *entity.SAMLConnection) *SAMLConnectionResponse {
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
