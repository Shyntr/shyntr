package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/internal/adapters/audit"
	"github.com/Shyntr/shyntr/internal/adapters/http/handlers"
	ldapadapter "github.com/Shyntr/shyntr/internal/adapters/ldap"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/repository"
	"github.com/Shyntr/shyntr/internal/application/mapper"
	"github.com/Shyntr/shyntr/internal/application/security"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	ldaplib "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"gorm.io/gorm"
)

// createLDAPFixture inserts an active LDAP connection into the test DB.
func createLDAPFixture(t *testing.T, db *gorm.DB, tenantID, connectionID, serverURL string) {
	t.Helper()
	require.NoError(t, db.Create(&models.LDAPConnectionGORM{
		ID:               connectionID,
		TenantID:         tenantID,
		Name:             "Test LDAP",
		ServerURL:        serverURL,
		BaseDN:           "dc=example,dc=org",
		UserSearchFilter: "(uid={0})",
		Active:           true,
	}).Error)
}

// buildLDAPHandlerRouter returns a router from the E2E env plus the LDAP POST endpoint.
func buildLDAPHandlerRouter(t *testing.T) *oidcE2EEnv {
	t.Helper()
	env := setupOIDCE2EEnv(t)
	cfg := env.cfg
	db := env.db

	appSecretBytes := []byte(cfg.AppSecret)
	auditLogger := audit.NewAuditLogger(db)
	policyRepo := repository.NewOutboundPolicyRepository(db)
	outboundGuard := security.NewOutboundGuard(policyRepo, cfg.SkipTLSVerify)
	ldapRepo := repository.NewLDAPConnectionRepository(db, appSecretBytes)
	scopeRepo := repository.NewScopeRepository(db)
	scopeUseCase := usecase.NewScopeUseCase(scopeRepo, auditLogger)
	dialer := ldapadapter.NewLDAPDialer()
	ldapUseCase := usecase.NewLDAPConnectionUseCase(ldapRepo, dialer, auditLogger, scopeUseCase, outboundGuard)

	requestRepo := repository.NewAuthRequestRepository(db)
	authUseCase := usecase.NewAuthUseCase(requestRepo, auditLogger)
	webhookRepo := repository.NewWebhookRepository(db)
	webhookEventRepo := repository.NewWebhookEventRepository(db)
	webhookUseCase := usecase.NewWebhookUseCase(webhookRepo, webhookEventRepo, auditLogger, outboundGuard)

	ldapHandler := handlers.NewLDAPHandler(cfg, authUseCase, ldapUseCase, webhookUseCase, mapper.New())
	env.router.POST("/t/:tenant_id/ldap/login/:connection_id", ldapHandler.Login)
	return env
}

// startLDAPChallenge starts an OIDC auth flow and returns the login_challenge.
func startLDAPChallenge(t *testing.T, env *oidcE2EEnv) string {
	t.Helper()
	codeVerifier := "e2e-code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"
	codeChallenge := pkceS256Challenge(codeVerifier)
	authURL := "/t/tenant-a/oauth2/auth?client_id=oidc-client-a&response_type=code&redirect_uri=" +
		url.QueryEscape("http://client.localhost/callback") +
		"&scope=openid%20profile&state=ldap-test&code_challenge=" + url.QueryEscape(codeChallenge) +
		"&code_challenge_method=S256"

	authResp := serveRequest(t, env.router, http.MethodGet, authURL, nil, nil)
	require.Equal(t, http.StatusFound, authResp.Code)
	loginChallenge := parseLocationQuery(t, authResp.Header().Get("Location")).Get("login_challenge")
	require.NotEmpty(t, loginChallenge)
	return loginChallenge
}

func TestLDAPHandler_Login_BadJSON(t *testing.T) {
	env := buildLDAPHandlerRouter(t)

	w := serveRequest(t, env.router, http.MethodPost,
		"/t/tenant-a/ldap/login/conn-1",
		bytes.NewBufferString("not-json"),
		map[string]string{"Content-Type": "application/json"},
	)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLDAPHandler_Login_MissingRequiredFields(t *testing.T) {
	env := buildLDAPHandlerRouter(t)

	body, _ := json.Marshal(map[string]string{
		// login_challenge intentionally missing; binding should fail
		"username": "alice",
		"password": "secret",
	})
	w := serveRequest(t, env.router, http.MethodPost,
		"/t/tenant-a/ldap/login/conn-1",
		bytes.NewReader(body),
		map[string]string{"Content-Type": "application/json"},
	)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLDAPHandler_Login_ExpiredChallenge(t *testing.T) {
	env := buildLDAPHandlerRouter(t)

	body, _ := json.Marshal(map[string]string{
		"login_challenge": "nonexistent-challenge-xyz-123",
		"username":        "alice",
		"password":        "secret",
	})
	w := serveRequest(t, env.router, http.MethodPost,
		"/t/tenant-a/ldap/login/conn-1",
		bytes.NewReader(body),
		map[string]string{"Content-Type": "application/json"},
	)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestLDAPHandler_Login_Unreachable(t *testing.T) {
	env := buildLDAPHandlerRouter(t)

	// Insert LDAP connection pointing to a port that is always unreachable.
	createLDAPFixture(t, env.db, "tenant-a", "ldap-unreachable", "ldap://127.0.0.1:1")
	loginChallenge := startLDAPChallenge(t, env)

	body, _ := json.Marshal(map[string]string{
		"login_challenge": loginChallenge,
		"username":        "alice",
		"password":        "secret",
	})
	w := serveRequest(t, env.router, http.MethodPost,
		"/t/tenant-a/ldap/login/ldap-unreachable",
		bytes.NewReader(body),
		map[string]string{"Content-Type": "application/json"},
	)
	// Auth failed due to unreachable LDAP — should be 401.
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_credentials")
}

// startOpenLDAPForHandler starts an openldap container for handler-level tests.
func startOpenLDAPForHandler(t *testing.T) (host, port string) {
	t.Helper()
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "osixia/openldap:1.5.0",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"LDAP_ORGANISATION":   "Example Inc.",
			"LDAP_DOMAIN":         "example.org",
			"LDAP_ADMIN_PASSWORD": "admin",
		},
		WaitingFor: wait.ForLog("slapd starting").WithStartupTimeout(90 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil && handlerDockerUnavailable(err) {
		t.Skipf("requires Docker: %v", err)
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })
	h, err := container.Host(ctx)
	require.NoError(t, err)
	p, err := container.MappedPort(ctx, "389/tcp")
	require.NoError(t, err)
	return h, p.Port()
}

// relaxLDAPOutboundPolicy opens the LDAP outbound policy to allow loopback/Docker connections.
func relaxLDAPOutboundPolicy(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Model(&models.OutboundPolicyGORM{}).
		Where("id = ?", "global-outbound-policy-ldap-auth").
		Updates(map[string]interface{}{
			"allowed_schemes_json":       `["ldap","ldaps"]`,
			"allowed_host_patterns_json": `["*"]`,
			"block_private_ips":          false,
			"block_loopback_ips":         false,
			"block_link_local_ips":       false,
			"block_multicast_ips":        false,
			"block_localhost_names":      false,
			"require_dns_resolve":        false,
		}).Error)
}

// setupDockerLDAPEnv wires up a full handler env pointed at a running Docker LDAP container.
func setupDockerLDAPEnv(t *testing.T, containerHost, containerPort string) *oidcE2EEnv {
	t.Helper()
	env := setupOIDCE2EEnv(t)
	cfg := env.cfg
	db := env.db

	relaxLDAPOutboundPolicy(t, db)

	appSecretBytes := []byte(cfg.AppSecret)
	auditLogger := audit.NewAuditLogger(db)
	policyRepo := repository.NewOutboundPolicyRepository(db)
	outboundGuard := security.NewOutboundGuard(policyRepo, cfg.SkipTLSVerify)
	ldapRepo := repository.NewLDAPConnectionRepository(db, appSecretBytes)
	scopeRepo := repository.NewScopeRepository(db)
	scopeUseCase := usecase.NewScopeUseCase(scopeRepo, auditLogger)
	dialer := ldapadapter.NewLDAPDialer()
	ldapUseCase := usecase.NewLDAPConnectionUseCase(ldapRepo, dialer, auditLogger, scopeUseCase, outboundGuard)

	requestRepo := repository.NewAuthRequestRepository(db)
	authUseCase := usecase.NewAuthUseCase(requestRepo, auditLogger)
	webhookRepo := repository.NewWebhookRepository(db)
	webhookEventRepo := repository.NewWebhookEventRepository(db)
	webhookUseCase := usecase.NewWebhookUseCase(webhookRepo, webhookEventRepo, auditLogger, outboundGuard)

	ldapHandler := handlers.NewLDAPHandler(cfg, authUseCase, ldapUseCase, webhookUseCase, mapper.New())
	env.router.POST("/t/:tenant_id/ldap/login/:connection_id", ldapHandler.Login)

	serverURL := fmt.Sprintf("ldap://%s:%s", containerHost, containerPort)
	require.NoError(t, db.Create(&models.LDAPConnectionGORM{
		ID:               "ldap-docker",
		TenantID:         "tenant-a",
		Name:             "Docker LDAP",
		ServerURL:        serverURL,
		BindDN:           "cn=admin,dc=example,dc=org",
		BaseDN:           "dc=example,dc=org",
		UserSearchFilter: "(uid={0})",
		Active:           true,
	}).Error)
	// Persist bind password via repo so it gets encrypted.
	conn, err := ldapRepo.GetByTenantAndID(context.Background(), "tenant-a", "ldap-docker")
	require.NoError(t, err)
	conn.BindPassword = "admin"
	require.NoError(t, ldapRepo.Update(context.Background(), conn))
	seedLDAPLoginUser(t, serverURL)

	return env
}

func seedLDAPLoginUser(t *testing.T, serverURL string) {
	t.Helper()

	l, err := ldaplib.DialURL(serverURL)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	require.NoError(t, l.Bind("cn=admin,dc=example,dc=org", "admin"))

	addReq := ldaplib.NewAddRequest("uid=alice,dc=example,dc=org", nil)
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	addReq.Attribute("uid", []string{"alice"})
	addReq.Attribute("cn", []string{"alice"})
	addReq.Attribute("sn", []string{"alice"})
	addReq.Attribute("userPassword", []string{"alice-password"})
	err = l.Add(addReq)
	if err != nil && !ldaplib.IsErrorWithCode(err, ldaplib.LDAPResultEntryAlreadyExists) {
		require.NoError(t, err)
	}
}

func TestLDAPHandler_Login_Success_OIDC(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	containerHost, containerPort := startOpenLDAPForHandler(t)
	env := setupDockerLDAPEnv(t, containerHost, containerPort)

	loginChallenge := startLDAPChallenge(t, env)

	body, _ := json.Marshal(map[string]string{
		"login_challenge": loginChallenge,
		"username":        "alice",
		"password":        "alice-password",
	})
	w := serveRequest(t, env.router, http.MethodPost,
		"/t/tenant-a/ldap/login/ldap-docker",
		bytes.NewReader(body),
		map[string]string{"Content-Type": "application/json"},
	)
	// Expect redirect (302) back to the relying party with login_verifier.
	assert.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	require.NotEmpty(t, loc)
	assert.Contains(t, loc, "login_verifier")
}

func TestLDAPHandler_Login_Success_SAML(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	containerHost, containerPort := startOpenLDAPForHandler(t)
	env := setupDockerLDAPEnv(t, containerHost, containerPort)

	// Insert a login request with protocol=saml directly into the DB.
	samlReqID := "saml-ldap-req-001"
	require.NoError(t, env.db.Create(&models.LoginRequestGORM{
		ID:            samlReqID,
		TenantID:      "tenant-a",
		ClientID:      "oidc-client-a",
		RequestURL:    "/oauth2/auth?client_id=oidc-client-a",
		Protocol:      "saml",
		Authenticated: false,
		Active:        true,
	}).Error)

	body, _ := json.Marshal(map[string]string{
		"login_challenge": samlReqID,
		"username":        "alice",
		"password":        "alice-password",
	})
	w := serveRequest(t, env.router, http.MethodPost,
		"/t/tenant-a/ldap/login/ldap-docker",
		bytes.NewReader(body),
		map[string]string{"Content-Type": "application/json"},
	)
	assert.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	require.NotEmpty(t, loc)
	assert.Contains(t, loc, "/saml/resume")
}

func handlerDockerUnavailable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "failed to create Docker provider") ||
		strings.Contains(msg, "permission denied while trying to connect to the docker API")
}
