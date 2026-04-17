package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/http/handlers"
	"github.com/Shyntr/shyntr/internal/application/mapper"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ldapHandlerAuthRepoStub struct {
	req        *model.LoginRequest
	getErr     error
	updatedReq *model.LoginRequest
	updateErr  error
}

func (r *ldapHandlerAuthRepoStub) SaveLoginRequest(context.Context, *model.LoginRequest) error {
	return nil
}
func (r *ldapHandlerAuthRepoStub) GetLoginRequest(context.Context, string) (*model.LoginRequest, error) {
	return r.req, r.getErr
}
func (r *ldapHandlerAuthRepoStub) GetRecentLogins(context.Context, string, int) ([]model.LoginRequest, error) {
	return nil, nil
}
func (r *ldapHandlerAuthRepoStub) GetAuthenticatedLoginRequest(context.Context, string) (*model.LoginRequest, error) {
	return nil, nil
}
func (r *ldapHandlerAuthRepoStub) GetAuthenticatedLoginRequestBySubject(context.Context, string, string) (*model.LoginRequest, error) {
	return nil, nil
}
func (r *ldapHandlerAuthRepoStub) GetLoginRequestBySessionToken(context.Context, string, string) (*model.LoginRequest, error) {
	return nil, nil
}
func (r *ldapHandlerAuthRepoStub) UpdateLoginRequest(_ context.Context, req *model.LoginRequest) error {
	r.updatedReq = req
	return r.updateErr
}
func (r *ldapHandlerAuthRepoStub) SaveConsentRequest(context.Context, *model.ConsentRequest) error {
	return nil
}
func (r *ldapHandlerAuthRepoStub) GetConsentRequest(context.Context, string) (*model.ConsentRequest, error) {
	return nil, nil
}
func (r *ldapHandlerAuthRepoStub) GetAuthenticatedConsentRequest(context.Context, string) (*model.ConsentRequest, error) {
	return nil, nil
}
func (r *ldapHandlerAuthRepoStub) GetAuthenticatedConsentRequestBySubject(context.Context, string) (*model.ConsentRequest, error) {
	return nil, nil
}
func (r *ldapHandlerAuthRepoStub) UpdateConsentRequest(context.Context, *model.ConsentRequest) error {
	return nil
}

type ldapHandlerLDAPRepoStub struct {
	conn            *model.LDAPConnection
	firstConn       *model.LDAPConnection
	firstErr        error
	secondErr       error
	getTenantIDCall int
}

func (r *ldapHandlerLDAPRepoStub) Create(context.Context, *model.LDAPConnection) error { return nil }
func (r *ldapHandlerLDAPRepoStub) GetByID(context.Context, string) (*model.LDAPConnection, error) {
	return r.conn, nil
}
func (r *ldapHandlerLDAPRepoStub) GetByTenantAndID(context.Context, string, string) (*model.LDAPConnection, error) {
	r.getTenantIDCall++
	if r.getTenantIDCall == 1 && (r.firstConn != nil || r.firstErr != nil) {
		return r.firstConn, r.firstErr
	}
	if r.getTenantIDCall >= 2 && r.secondErr != nil {
		return nil, r.secondErr
	}
	return r.conn, nil
}
func (r *ldapHandlerLDAPRepoStub) GetConnectionCount(context.Context, string) (int64, error) {
	return 0, nil
}
func (r *ldapHandlerLDAPRepoStub) Update(context.Context, *model.LDAPConnection) error { return nil }
func (r *ldapHandlerLDAPRepoStub) Delete(context.Context, string, string) error        { return nil }
func (r *ldapHandlerLDAPRepoStub) ListByTenant(context.Context, string) ([]*model.LDAPConnection, error) {
	return nil, nil
}
func (r *ldapHandlerLDAPRepoStub) ListActiveByTenant(context.Context, string) ([]*model.LDAPConnection, error) {
	return nil, nil
}
func (r *ldapHandlerLDAPRepoStub) List(context.Context) ([]*model.LDAPConnection, error) {
	return nil, nil
}

type ldapHandlerSessionStub struct {
	entry   *model.LDAPEntry
	authErr error
}

func (s *ldapHandlerSessionStub) Authenticate(context.Context, string, string) error {
	return s.authErr
}
func (s *ldapHandlerSessionStub) Search(context.Context, string, []string) ([]model.LDAPEntry, error) {
	if s.entry == nil {
		return nil, nil
	}
	return []model.LDAPEntry{*s.entry}, nil
}
func (s *ldapHandlerSessionStub) Close() error { return nil }

type ldapHandlerDialerStub struct {
	session port.LDAPSession
	err     error
}

func (d *ldapHandlerDialerStub) Dial(context.Context, *model.LDAPConnection) (port.LDAPSession, error) {
	return d.session, d.err
}

type ldapHandlerAuditStub struct{}

func (a *ldapHandlerAuditStub) Log(string, string, string, string, string, map[string]interface{}) {}

type ldapHandlerWebhookStub struct {
	eventType string
	data      map[string]interface{}
}

func (w *ldapHandlerWebhookStub) CreateWebhook(context.Context, *model.Webhook, string, string) (*model.Webhook, string, error) {
	return nil, "", nil
}
func (w *ldapHandlerWebhookStub) GetWebhook(context.Context, string) (*model.Webhook, error) {
	return nil, nil
}
func (w *ldapHandlerWebhookStub) DeleteWebhook(context.Context, string, string, string) error {
	return nil
}
func (w *ldapHandlerWebhookStub) ListWebhooks(context.Context) ([]*model.Webhook, error) {
	return nil, nil
}
func (w *ldapHandlerWebhookStub) FireEvent(_ string, eventType string, data map[string]interface{}) {
	w.eventType = eventType
	w.data = data
}
func (w *ldapHandlerWebhookStub) StartDispatcher() {}

func buildBranchLDAPHandlerRouter(t *testing.T, authRepo *ldapHandlerAuthRepoStub, ldapRepo *ldapHandlerLDAPRepoStub, session port.LDAPSession) (*gin.Engine, *ldapHandlerWebhookStub) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	logger.InitLogger("info")

	authUC := usecase.NewAuthUseCase(authRepo, &ldapHandlerAuditStub{})
	ldapUC := usecase.NewLDAPConnectionUseCase(ldapRepo, &ldapHandlerDialerStub{session: session}, &ldapHandlerAuditStub{}, nil, nil)
	webhookUC := &ldapHandlerWebhookStub{}
	cfg := &config.Config{BaseIssuerURL: "http://issuer.test"}

	r := gin.New()
	h := handlers.NewLDAPHandler(cfg, authUC, ldapUC, webhookUC, mapper.New())
	r.POST("/t/:tenant_id/ldap/login/:connection_id", h.Login)
	return r, webhookUC
}

func TestLDAPHandler_Login_BranchCases(t *testing.T) {
	makeBody := func(challenge, username, password string) *bytes.Reader {
		body, err := json.Marshal(map[string]string{
			"login_challenge": challenge,
			"username":        username,
			"password":        password,
		})
		require.NoError(t, err)
		return bytes.NewReader(body)
	}

	baseConn := &model.LDAPConnection{
		ID:       "ldap-1",
		TenantID: "tenant-a",
		Name:     "Corp LDAP",
		AttributeMapping: map[string]model.AttributeMappingRule{
			"sub": {Source: "uid", Type: "string"},
		},
	}
	baseEntry := &model.LDAPEntry{
		DN: "uid=alice,dc=example,dc=org",
		Attributes: map[string][]string{
			"uid":   {"alice"},
			"email": {"alice@example.com"},
		},
	}

	t.Run("wrong password returns 401 structured error", func(t *testing.T) {
		authRepo := &ldapHandlerAuthRepoStub{req: &model.LoginRequest{ID: "challenge-1", TenantID: "tenant-a", ClientID: "client-a", RequestURL: "/oauth2/auth", Active: true}}
		router, _ := buildBranchLDAPHandlerRouter(t, authRepo, &ldapHandlerLDAPRepoStub{conn: baseConn}, &ldapHandlerSessionStub{entry: baseEntry, authErr: errors.New("bad password")})

		w := serveRequest(t, router, http.MethodPost, "/t/tenant-a/ldap/login/ldap-1", makeBody("challenge-1", "alice", "wrong"), map[string]string{"Content-Type": "application/json"})
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), `"error":"invalid_credentials"`)
	})

	t.Run("inactive challenge currently returns 404", func(t *testing.T) {
		authRepo := &ldapHandlerAuthRepoStub{req: &model.LoginRequest{ID: "challenge-2", TenantID: "tenant-a", ClientID: "client-a", RequestURL: "/oauth2/auth", Active: false, Authenticated: false}}
		router, _ := buildBranchLDAPHandlerRouter(t, authRepo, &ldapHandlerLDAPRepoStub{conn: baseConn}, &ldapHandlerSessionStub{entry: baseEntry})

		w := serveRequest(t, router, http.MethodPost, "/t/tenant-a/ldap/login/ldap-1", makeBody("challenge-2", "alice", "secret"), map[string]string{"Content-Type": "application/json"})
		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), `"error":"login_request_not_found"`)
	})

	t.Run("get connection fails after auth succeeds", func(t *testing.T) {
		authRepo := &ldapHandlerAuthRepoStub{req: &model.LoginRequest{ID: "challenge-3", TenantID: "tenant-a", ClientID: "client-a", RequestURL: "/oauth2/auth", Active: true}}
		ldapRepo := &ldapHandlerLDAPRepoStub{firstConn: baseConn, secondErr: errors.New("connection missing")}
		router, _ := buildBranchLDAPHandlerRouter(t, authRepo, ldapRepo, &ldapHandlerSessionStub{entry: baseEntry})

		w := serveRequest(t, router, http.MethodPost, "/t/tenant-a/ldap/login/ldap-1", makeBody("challenge-3", "alice", "secret"), map[string]string{"Content-Type": "application/json"})
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), `"error":"server_error"`)
	})

	t.Run("sub already set is not overwritten by dn", func(t *testing.T) {
		authRepo := &ldapHandlerAuthRepoStub{req: &model.LoginRequest{ID: "challenge-4", TenantID: "tenant-a", ClientID: "client-a", RequestURL: "/oauth2/auth?client_id=client-a", Active: true}}
		router, webhook := buildBranchLDAPHandlerRouter(t, authRepo, &ldapHandlerLDAPRepoStub{conn: baseConn}, &ldapHandlerSessionStub{entry: baseEntry})

		w := serveRequest(t, router, http.MethodPost, "/t/tenant-a/ldap/login/ldap-1", makeBody("challenge-4", "alice", "secret"), map[string]string{"Content-Type": "application/json"})
		assert.Equal(t, http.StatusFound, w.Code)
		require.NotNil(t, authRepo.updatedReq)

		var ctxData map[string]interface{}
		require.NoError(t, json.Unmarshal(authRepo.updatedReq.Context, &ctxData))
		loginClaims, ok := ctxData["login_claims"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "alice", loginClaims["sub"])
		assert.Equal(t, "user.login.ext", webhook.eventType)
	})

	t.Run("request url parse failure returns 500", func(t *testing.T) {
		authRepo := &ldapHandlerAuthRepoStub{req: &model.LoginRequest{ID: "challenge-5", TenantID: "tenant-a", ClientID: "client-a", RequestURL: "http://%zz", Active: true}}
		router, _ := buildBranchLDAPHandlerRouter(t, authRepo, &ldapHandlerLDAPRepoStub{conn: baseConn}, &ldapHandlerSessionStub{entry: baseEntry})

		w := serveRequest(t, router, http.MethodPost, "/t/tenant-a/ldap/login/ldap-1", makeBody("challenge-5", "alice", "secret"), map[string]string{"Content-Type": "application/json"})
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), `"error":"server_error"`)
	})
}
