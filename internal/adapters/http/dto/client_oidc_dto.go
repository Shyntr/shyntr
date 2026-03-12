package dto

import (
	"github.com/Shyntr/shyntr/internal/domain/entity"
	"github.com/go-jose/go-jose/v3"
)

type CreateOAuth2ClientRequest struct {
	ID                      string              `json:"client_id" example:"my-web-app"`
	TenantID                string              `json:"tenant_id" binding:"required" example:"default"`
	Name                    string              `json:"name" binding:"required" example:"My Frontend Application"`
	Secret                  string              `json:"client_secret" example:"super-secure-secret-key"`
	RedirectURIs            []string            `json:"redirect_uris" binding:"required" example:"https://app.example.com/callback"`
	GrantTypes              []string            `json:"grant_types" binding:"required" example:"authorization_code,refresh_token"`
	ResponseTypes           []string            `json:"response_types" example:"code"`
	ResponseModes           []string            `json:"response_modes" example:"query,form_post"`
	Scopes                  []string            `json:"scopes" example:"openid,profile,email,offline_access"`
	Audience                []string            `json:"audience" example:"api-service"`
	Public                  bool                `json:"public" example:"false"`
	TokenEndpointAuthMethod string              `json:"token_endpoint_auth_method" example:"client_secret_basic"`
	EnforcePKCE             bool                `json:"enforce_pkce" example:"true"`
	AllowedCORSOrigins      []string            `json:"allowed_cors_origins" example:"https://app.example.com"`
	PostLogoutRedirectURIs  []string            `json:"post_logout_redirect_uris" example:"https://app.example.com/logout"`
	BackchannelLogoutURI    string              `json:"backchannel_logout_uri" example:"https://api.example.com/backchannel-logout"`
	SubjectType             string              `json:"subject_type" example:"public"`
	JWKS                    *jose.JSONWebKeySet `json:"jwks" swaggertype:"object"`
}

type OAuth2ClientResponse struct {
	ID                      string              `json:"client_id" example:"my-web-app"`
	TenantID                string              `json:"tenant_id" example:"default"`
	Name                    string              `json:"name" example:"My Frontend Application"`
	AppID                   string              `json:"app_id" example:"app-xyz123"`
	Secret                  string              `json:"client_secret,omitempty" example:"super-secure-secret-key"`
	RedirectURIs            []string            `json:"redirect_uris" example:"https://app.example.com/callback"`
	GrantTypes              []string            `json:"grant_types" example:"authorization_code,refresh_token"`
	ResponseTypes           []string            `json:"response_types" example:"code"`
	ResponseModes           []string            `json:"response_modes" example:"query,form_post"`
	Scopes                  []string            `json:"scopes" example:"openid,profile,email,offline_access"`
	Audience                []string            `json:"audience" example:"api-service"`
	Public                  bool                `json:"public" example:"false"`
	TokenEndpointAuthMethod string              `json:"token_endpoint_auth_method" example:"client_secret_basic"`
	EnforcePKCE             bool                `json:"enforce_pkce" example:"true"`
	AllowedCORSOrigins      []string            `json:"allowed_cors_origins" example:"https://app.example.com"`
	PostLogoutRedirectURIs  []string            `json:"post_logout_redirect_uris" example:"https://app.example.com/logout"`
	BackchannelLogoutURI    string              `json:"backchannel_logout_uri" example:"https://api.example.com/backchannel-logout"`
	AccessTokenLifespan     string              `json:"access_token_lifespan,omitempty" example:"1h"`
	RefreshTokenLifespan    string              `json:"refresh_token_lifespan,omitempty" example:"720h"`
	IDTokenLifespan         string              `json:"id_token_lifespan,omitempty" example:"1h"`
	SubjectType             string              `json:"subject_type" example:"public"`
	JWKS                    *jose.JSONWebKeySet `json:"jwks,omitempty" swaggertype:"object"`
	CreatedAt               string              `json:"created_at" example:"2026-03-12T15:04:05Z"`
	UpdatedAt               string              `json:"updated_at,omitempty" example:"2026-03-12T15:04:05Z"`
}

func (req *CreateOAuth2ClientRequest) ToDomain() *entity.OAuth2Client {
	return &entity.OAuth2Client{
		ID:                      req.ID,
		TenantID:                req.TenantID,
		Name:                    req.Name,
		Secret:                  req.Secret,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		ResponseModes:           req.ResponseModes,
		Scopes:                  req.Scopes,
		Audience:                req.Audience,
		Public:                  req.Public,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		EnforcePKCE:             req.EnforcePKCE,
		AllowedCORSOrigins:      req.AllowedCORSOrigins,
		PostLogoutRedirectURIs:  req.PostLogoutRedirectURIs,
		BackchannelLogoutURI:    req.BackchannelLogoutURI,
		SubjectType:             req.SubjectType,
		JSONWebKeys:             req.JWKS,
	}
}

func FromDomainOAuth2Client(c *entity.OAuth2Client) *OAuth2ClientResponse {
	return &OAuth2ClientResponse{
		ID:                      c.ID,
		TenantID:                c.TenantID,
		Name:                    c.Name,
		AppID:                   c.AppID,
		Secret:                  c.Secret,
		RedirectURIs:            c.RedirectURIs,
		GrantTypes:              c.GrantTypes,
		ResponseTypes:           c.ResponseTypes,
		ResponseModes:           c.ResponseModes,
		Scopes:                  c.Scopes,
		Audience:                c.Audience,
		Public:                  c.Public,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		EnforcePKCE:             c.EnforcePKCE,
		AllowedCORSOrigins:      c.AllowedCORSOrigins,
		PostLogoutRedirectURIs:  c.PostLogoutRedirectURIs,
		BackchannelLogoutURI:    c.BackchannelLogoutURI,
		SubjectType:             c.SubjectType,
		JWKS:                    c.JSONWebKeys,
		AccessTokenLifespan:     c.AccessTokenLifespan,
		RefreshTokenLifespan:    c.RefreshTokenLifespan,
		IDTokenLifespan:         c.IDTokenLifespan,
		CreatedAt:               c.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:               c.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

func FromDomainOAuth2Clients(clients []*entity.OAuth2Client) []*OAuth2ClientResponse {
	responses := make([]*OAuth2ClientResponse, 0, len(clients))

	for i := range clients {
		responses = append(responses, FromDomainOAuth2Client(clients[i]))
	}

	return responses
}
