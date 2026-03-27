package usecase

import (
	"context"
	"errors"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
)

type ManagementUseCase interface {
	GetLoginMethods(ctx context.Context, challenge string) ([]model.AuthMethod, *model.LoginRequest, error)
}

type managementUseCase struct {
	Config   *config.Config
	AuthReq  port.AuthRequestRepository
	OidcConn port.OIDCConnectionRepository
	SamlConn port.SAMLConnectionRepository
}

func NewManagementUseCase(Config *config.Config, AuthReq port.AuthRequestRepository,
	OidcConn port.OIDCConnectionRepository,
	SamlConn port.SAMLConnectionRepository) ManagementUseCase {
	return &managementUseCase{Config: Config, AuthReq: AuthReq, OidcConn: OidcConn, SamlConn: SamlConn}
}

func (m *managementUseCase) GetLoginMethods(ctx context.Context, challenge string) ([]model.AuthMethod, *model.LoginRequest, error) {
	loginReq, err := m.AuthReq.GetLoginRequest(ctx, challenge)
	if err != nil {
		return nil, nil, err
	}

	if loginReq.Authenticated {
		return nil, nil, errors.New("already authenticated")
	}

	tenantID := loginReq.TenantID
	samlConns, err := m.SamlConn.ListActiveByTenant(ctx, tenantID)
	oidcConns, err := m.OidcConn.ListActiveByTenant(ctx, tenantID)
	methods := []model.AuthMethod{}

	//TODO this will be configured by tenants
	if tenantID == "default" {
		methods = append(methods, model.AuthMethod{
			ID:   "basic-auth",
			Type: "password",
			Name: "Username & Password",
		})
	}

	for _, conn := range samlConns {
		methods = append(methods, model.AuthMethod{
			ID:       conn.ID,
			Type:     "saml",
			Name:     conn.Name,
			LoginURL: m.Config.BaseIssuerURL + "/t/" + tenantID + "/saml/login/" + conn.ID + "?login_challenge=" + challenge,
		})
	}

	for _, conn := range oidcConns {
		methods = append(methods, model.AuthMethod{
			ID:       conn.ID,
			Type:     "oidc",
			Name:     conn.Name,
			LoginURL: m.Config.BaseIssuerURL + "/t/" + tenantID + "/oidc/login/" + conn.ID + "?login_challenge=" + challenge,
		})
	}
	return methods, loginReq, nil
}
