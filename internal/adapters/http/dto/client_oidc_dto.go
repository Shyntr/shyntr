package dto

import "github.com/nevzatcirak/shyntr/internal/domain/entity"

type CreateOAuth2ClientRequest struct {
	ID                      string   `json:"client_id"`
	TenantID                string   `json:"tenant_id" binding:"required"`
	Name                    string   `json:"name" binding:"required"`
	Secret                  string   `json:"client_secret"`
	RedirectURIs            []string `json:"redirect_uris" binding:"required"`
	GrantTypes              []string `json:"grant_types" binding:"required"`
	ResponseTypes           []string `json:"response_types"`
	ResponseModes           []string `json:"response_modes"`
	Scopes                  []string `json:"scopes"`
	Audience                []string `json:"audience"`
	Public                  bool     `json:"public"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	EnforcePKCE             bool     `json:"enforce_pkce"`
	AllowedCORSOrigins      []string `json:"allowed_cors_origins"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	BackchannelLogoutURI    string   `json:"backchannel_logout_uri"`
	SubjectType             string   `json:"subject_type"`
}

type OAuth2ClientResponse struct {
	ID                      string   `json:"client_id"`
	TenantID                string   `json:"tenant_id"`
	Name                    string   `json:"name"`
	AppID                   string   `json:"app_id"`
	Secret                  string   `json:"client_secret"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ResponseModes           []string `json:"response_modes"`
	Scopes                  []string `json:"scopes"`
	Audience                []string `json:"audience"`
	Public                  bool     `json:"public"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	EnforcePKCE             bool     `json:"enforce_pkce"`
	AllowedCORSOrigins      []string `json:"allowed_cors_origins"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	BackchannelLogoutURI    string   `json:"backchannel_logout_uri"`
	AccessTokenLifespan     string   `json:"access_token_lifespan,omitempty"`
	RefreshTokenLifespan    string   `json:"refresh_token_lifespan,omitempty"`
	IDTokenLifespan         string   `json:"id_token_lifespan,omitempty"`
	SubjectType             string   `json:"subject_type"`
	CreatedAt               string   `json:"created_at"`
	UpdatedAt               string   `json:"updated_at,omitempty"`
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
