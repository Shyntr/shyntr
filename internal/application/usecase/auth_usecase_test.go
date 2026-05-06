package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/stretchr/testify/require"
)

type authRequestRepoStub struct {
	login *model.LoginRequest
}

func (r *authRequestRepoStub) SaveLoginRequest(context.Context, *model.LoginRequest) error {
	return nil
}

func (r *authRequestRepoStub) GetLoginRequest(_ context.Context, _ string) (*model.LoginRequest, error) {
	if r.login == nil {
		return nil, errors.New("login request not found")
	}
	copy := *r.login
	return &copy, nil
}

func (r *authRequestRepoStub) GetRecentLogins(context.Context, string, int) ([]model.LoginRequest, error) {
	return nil, nil
}

func (r *authRequestRepoStub) GetAuthenticatedLoginRequest(context.Context, string, string) (*model.LoginRequest, error) {
	return nil, nil
}

func (r *authRequestRepoStub) GetAuthenticatedLoginRequestBySubject(context.Context, string, string) (*model.LoginRequest, error) {
	return nil, nil
}

func (r *authRequestRepoStub) GetLoginRequestBySessionToken(context.Context, string, string) (*model.LoginRequest, error) {
	return nil, nil
}

func (r *authRequestRepoStub) UpdateLoginRequest(_ context.Context, req *model.LoginRequest) error {
	copy := *req
	r.login = &copy
	return nil
}

func (r *authRequestRepoStub) SaveConsentRequest(context.Context, *model.ConsentRequest) error {
	return nil
}

func (r *authRequestRepoStub) GetConsentRequest(context.Context, string) (*model.ConsentRequest, error) {
	return nil, nil
}

func (r *authRequestRepoStub) GetAuthenticatedConsentRequest(context.Context, string) (*model.ConsentRequest, error) {
	return nil, nil
}

func (r *authRequestRepoStub) GetAuthenticatedConsentRequestBySubject(context.Context, string) (*model.ConsentRequest, error) {
	return nil, nil
}

func (r *authRequestRepoStub) UpdateConsentRequest(context.Context, *model.ConsentRequest) error {
	return nil
}

type authAuditStub struct{}

func (a *authAuditStub) Log(string, string, string, string, string, map[string]interface{}) {}

func TestAuthUseCase_AcceptLoginRequest_PersistsNormalizedContext(t *testing.T) {
	t.Parallel()

	repo := &authRequestRepoStub{login: &model.LoginRequest{
		ID:         "login-challenge",
		TenantID:   "tenant-a",
		ClientID:   "client-a",
		RequestURL: "/oauth2/auth",
		Protocol:   "oidc",
		Active:     true,
	}}
	uc := NewAuthUseCase(repo, &authAuditStub{})

	login, err := uc.AcceptLoginRequest(
		context.Background(),
		"login-challenge",
		false,
		0,
		"ext:12345",
		map[string]interface{}{
			"identity": map[string]interface{}{
				"attributes": map[string]interface{}{
					"preferred_username": "alice",
					"email":              "alice@example.com",
					"name":               "Alice Doe",
				},
				"groups": []interface{}{"engineering"},
				"roles":  []interface{}{},
			},
			"authentication": map[string]interface{}{
				"amr":              []interface{}{"pwd"},
				"authenticated_at": "2026-04-23T18:30:00Z",
			},
		},
		"127.0.0.1",
		"test",
	)

	require.NoError(t, err)
	require.True(t, login.Authenticated)
	require.False(t, login.Active)
	require.Equal(t, "ext:12345", login.Subject)

	normalized, ok, err := repo.login.NormalizedContext()
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "alice", normalized.Identity.Attributes["preferred_username"])
	require.Equal(t, []string{"engineering"}, normalized.Identity.Groups)
	require.Equal(t, []string{"pwd"}, normalized.Authentication.AMR)

	var stored map[string]interface{}
	require.NoError(t, json.Unmarshal(repo.login.Context, &stored))
	require.Contains(t, stored, "identity")
	require.Contains(t, stored, "authentication")
}

func TestAuthUseCase_AcceptLoginRequest_RejectsInvalidNormalizedContext(t *testing.T) {
	t.Parallel()

	repo := &authRequestRepoStub{login: &model.LoginRequest{
		ID:       "login-challenge",
		TenantID: "tenant-a",
		ClientID: "client-a",
		Active:   true,
	}}
	uc := NewAuthUseCase(repo, &authAuditStub{})

	_, err := uc.AcceptLoginRequest(
		context.Background(),
		"login-challenge",
		false,
		0,
		"ext:12345",
		map[string]interface{}{
			"authentication": map[string]interface{}{
				"amr": []interface{}{"pwd", ""},
			},
		},
		"127.0.0.1",
		"test",
	)

	require.ErrorContains(t, err, "authentication amr must not contain empty values")
	require.False(t, repo.login.Authenticated)
	require.Nil(t, repo.login.Context)
}
