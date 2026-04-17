package usecase_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Stubs for management_usecase tests
// ---------------------------------------------------------------------------

type stubAuthReqRepo struct {
	req *model.LoginRequest
	err error
}

func (r *stubAuthReqRepo) SaveLoginRequest(_ context.Context, _ *model.LoginRequest) error {
	return nil
}
func (r *stubAuthReqRepo) GetLoginRequest(_ context.Context, _ string) (*model.LoginRequest, error) {
	return r.req, r.err
}
func (r *stubAuthReqRepo) GetRecentLogins(_ context.Context, _ string, _ int) ([]model.LoginRequest, error) {
	return nil, nil
}
func (r *stubAuthReqRepo) GetAuthenticatedLoginRequest(_ context.Context, _ string) (*model.LoginRequest, error) {
	return r.req, r.err
}
func (r *stubAuthReqRepo) GetAuthenticatedLoginRequestBySubject(_ context.Context, _, _ string) (*model.LoginRequest, error) {
	return r.req, r.err
}
func (r *stubAuthReqRepo) GetLoginRequestBySessionToken(_ context.Context, _, _ string) (*model.LoginRequest, error) {
	return r.req, r.err
}
func (r *stubAuthReqRepo) UpdateLoginRequest(_ context.Context, _ *model.LoginRequest) error {
	return nil
}
func (r *stubAuthReqRepo) SaveConsentRequest(_ context.Context, _ *model.ConsentRequest) error {
	return nil
}
func (r *stubAuthReqRepo) GetConsentRequest(_ context.Context, _ string) (*model.ConsentRequest, error) {
	return nil, nil
}
func (r *stubAuthReqRepo) GetAuthenticatedConsentRequest(_ context.Context, _ string) (*model.ConsentRequest, error) {
	return nil, nil
}
func (r *stubAuthReqRepo) GetAuthenticatedConsentRequestBySubject(_ context.Context, _ string) (*model.ConsentRequest, error) {
	return nil, nil
}
func (r *stubAuthReqRepo) UpdateConsentRequest(_ context.Context, _ *model.ConsentRequest) error {
	return nil
}

// stubOIDCConnRepo is a minimal OIDC connection repository stub.
type stubOIDCConnRepo struct {
	active []*model.OIDCConnection
	err    error
}

func (r *stubOIDCConnRepo) Create(_ context.Context, _ *model.OIDCConnection) error { return nil }
func (r *stubOIDCConnRepo) GetByID(_ context.Context, _ string) (*model.OIDCConnection, error) {
	return nil, nil
}
func (r *stubOIDCConnRepo) GetByTenantAndID(_ context.Context, _, _ string) (*model.OIDCConnection, error) {
	return nil, nil
}
func (r *stubOIDCConnRepo) GetConnectionCount(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
func (r *stubOIDCConnRepo) Update(_ context.Context, _ *model.OIDCConnection) error { return nil }
func (r *stubOIDCConnRepo) Delete(_ context.Context, _, _ string) error             { return nil }
func (r *stubOIDCConnRepo) ListByTenant(_ context.Context, _ string) ([]*model.OIDCConnection, error) {
	return nil, nil
}
func (r *stubOIDCConnRepo) ListActiveByTenant(_ context.Context, _ string) ([]*model.OIDCConnection, error) {
	return r.active, r.err
}
func (r *stubOIDCConnRepo) List(_ context.Context) ([]*model.OIDCConnection, error) {
	return nil, nil
}

// stubSAMLConnRepo is a minimal SAML connection repository stub.
type stubSAMLConnRepo struct {
	active []*model.SAMLConnection
	err    error
}

func (r *stubSAMLConnRepo) Create(_ context.Context, _ *model.SAMLConnection) error { return nil }
func (r *stubSAMLConnRepo) GetByID(_ context.Context, _ string) (*model.SAMLConnection, error) {
	return nil, nil
}
func (r *stubSAMLConnRepo) GetByTenantAndID(_ context.Context, _, _ string) (*model.SAMLConnection, error) {
	return nil, nil
}
func (r *stubSAMLConnRepo) GetConnectionCount(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
func (r *stubSAMLConnRepo) GetConnectionByIdpEntity(_ context.Context, _, _ string) (*model.SAMLConnection, error) {
	return nil, nil
}
func (r *stubSAMLConnRepo) Update(_ context.Context, _ *model.SAMLConnection) error { return nil }
func (r *stubSAMLConnRepo) Delete(_ context.Context, _, _ string) error             { return nil }
func (r *stubSAMLConnRepo) ListByTenant(_ context.Context, _ string) ([]*model.SAMLConnection, error) {
	return nil, nil
}
func (r *stubSAMLConnRepo) ListActiveByTenant(_ context.Context, _ string) ([]*model.SAMLConnection, error) {
	return r.active, r.err
}
func (r *stubSAMLConnRepo) List(_ context.Context) ([]*model.SAMLConnection, error) {
	return nil, nil
}

// stubMgmtLDAPRepo is a minimal LDAP connection repository stub for management tests.
type stubMgmtLDAPRepo struct {
	active []*model.LDAPConnection
	err    error
}

func (r *stubMgmtLDAPRepo) Create(_ context.Context, _ *model.LDAPConnection) error { return nil }
func (r *stubMgmtLDAPRepo) GetByID(_ context.Context, _ string) (*model.LDAPConnection, error) {
	return nil, nil
}
func (r *stubMgmtLDAPRepo) GetByTenantAndID(_ context.Context, _, _ string) (*model.LDAPConnection, error) {
	return nil, nil
}
func (r *stubMgmtLDAPRepo) GetConnectionCount(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
func (r *stubMgmtLDAPRepo) Update(_ context.Context, _ *model.LDAPConnection) error { return nil }
func (r *stubMgmtLDAPRepo) Delete(_ context.Context, _, _ string) error             { return nil }
func (r *stubMgmtLDAPRepo) ListByTenant(_ context.Context, _ string) ([]*model.LDAPConnection, error) {
	return nil, nil
}
func (r *stubMgmtLDAPRepo) ListActiveByTenant(_ context.Context, _ string) ([]*model.LDAPConnection, error) {
	return r.active, r.err
}
func (r *stubMgmtLDAPRepo) List(_ context.Context) ([]*model.LDAPConnection, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Helper to build a ManagementUseCase with stub repos.
// ---------------------------------------------------------------------------

func buildManagementUseCase(
	authReq *stubAuthReqRepo,
	oidcRepo *stubOIDCConnRepo,
	samlRepo *stubSAMLConnRepo,
	ldapRepo *stubMgmtLDAPRepo,
) usecase.ManagementUseCase {
	cfg := &config.Config{BaseIssuerURL: "http://example.test"}
	return usecase.NewManagementUseCase(cfg, authReq, oidcRepo, samlRepo, ldapRepo)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestGetLoginMethods_AllThreeTypes(t *testing.T) {
	req := &model.LoginRequest{
		ID:            "challenge-001",
		TenantID:      "tenant-a",
		Authenticated: false,
	}
	authRepo := &stubAuthReqRepo{req: req}
	oidcRepo := &stubOIDCConnRepo{active: []*model.OIDCConnection{
		{ID: "oidc-1", Name: "Google", TenantID: "tenant-a", Active: true},
	}}
	samlRepo := &stubSAMLConnRepo{active: []*model.SAMLConnection{
		{ID: "saml-1", Name: "SAML IdP", TenantID: "tenant-a", Active: true},
	}}
	ldapRepo := &stubMgmtLDAPRepo{active: []*model.LDAPConnection{
		{ID: "ldap-1", Name: "Corp AD", TenantID: "tenant-a", Active: true},
	}}

	uc := buildManagementUseCase(authRepo, oidcRepo, samlRepo, ldapRepo)
	methods, loginReq, err := uc.GetLoginMethods(context.Background(), "challenge-001")

	require.NoError(t, err)
	require.NotNil(t, loginReq)
	assert.Equal(t, "challenge-001", loginReq.ID)

	typeSet := map[string]bool{}
	for _, m := range methods {
		typeSet[m.Type] = true
	}
	assert.True(t, typeSet["oidc"], "must include OIDC connection")
	assert.True(t, typeSet["saml"], "must include SAML connection")
	assert.True(t, typeSet["ldap"], "must include LDAP connection")
}

func TestGetLoginMethods_LDAPListError(t *testing.T) {
	req := &model.LoginRequest{
		ID:            "challenge-002",
		TenantID:      "tenant-a",
		Authenticated: false,
	}
	authRepo := &stubAuthReqRepo{req: req}
	oidcRepo := &stubOIDCConnRepo{}
	samlRepo := &stubSAMLConnRepo{}
	ldapRepo := &stubMgmtLDAPRepo{err: errors.New("db error")}

	uc := buildManagementUseCase(authRepo, oidcRepo, samlRepo, ldapRepo)
	_, _, err := uc.GetLoginMethods(context.Background(), "challenge-002")

	require.Error(t, err, "LDAP repo error must propagate")
}

func TestGetLoginMethods_Empty(t *testing.T) {
	req := &model.LoginRequest{
		ID:            "challenge-003",
		TenantID:      "tenant-a",
		Authenticated: false,
	}
	authRepo := &stubAuthReqRepo{req: req}
	oidcRepo := &stubOIDCConnRepo{}
	samlRepo := &stubSAMLConnRepo{}
	ldapRepo := &stubMgmtLDAPRepo{}

	uc := buildManagementUseCase(authRepo, oidcRepo, samlRepo, ldapRepo)
	methods, loginReq, err := uc.GetLoginMethods(context.Background(), "challenge-003")

	require.NoError(t, err)
	require.NotNil(t, loginReq)
	assert.Empty(t, methods, "must return empty slice when no connections exist")
}

func TestGetLoginMethods_ChallengeMissing(t *testing.T) {
	authRepo := &stubAuthReqRepo{req: nil, err: errors.New("login request not found")}
	oidcRepo := &stubOIDCConnRepo{}
	samlRepo := &stubSAMLConnRepo{}
	ldapRepo := &stubMgmtLDAPRepo{}

	uc := buildManagementUseCase(authRepo, oidcRepo, samlRepo, ldapRepo)
	_, _, err := uc.GetLoginMethods(context.Background(), "no-such-challenge")

	require.Error(t, err)
	assert.Equal(t, usecase.ErrLoginChallengeNotFound, err)
}

func TestGetLoginMethods_AlreadyAuthenticated(t *testing.T) {
	req := &model.LoginRequest{
		ID:            "challenge-auth",
		TenantID:      "tenant-a",
		Authenticated: true,
	}
	authRepo := &stubAuthReqRepo{req: req}
	oidcRepo := &stubOIDCConnRepo{}
	samlRepo := &stubSAMLConnRepo{}
	ldapRepo := &stubMgmtLDAPRepo{}

	uc := buildManagementUseCase(authRepo, oidcRepo, samlRepo, ldapRepo)
	_, _, err := uc.GetLoginMethods(context.Background(), "challenge-auth")

	require.Error(t, err)
	assert.Equal(t, usecase.ErrLoginAlreadyUsed, err)
}
