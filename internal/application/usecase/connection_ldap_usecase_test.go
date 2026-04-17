package usecase

// Internal test file (package usecase, not usecase_test) to allow testing
// unexported helpers (ldapEscapeFilter, classifyDialError) alongside the
// public AuthenticateUser method.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Stub: port.LDAPConnectionRepository
// ---------------------------------------------------------------------------

type stubLDAPRepo struct {
	conn *model.LDAPConnection
	err  error
}

func (r *stubLDAPRepo) Create(_ context.Context, _ *model.LDAPConnection) error { return nil }
func (r *stubLDAPRepo) GetByID(_ context.Context, _ string) (*model.LDAPConnection, error) {
	return r.conn, r.err
}
func (r *stubLDAPRepo) GetByTenantAndID(_ context.Context, _, _ string) (*model.LDAPConnection, error) {
	return r.conn, r.err
}
func (r *stubLDAPRepo) GetConnectionCount(_ context.Context, _ string) (int64, error) { return 0, nil }
func (r *stubLDAPRepo) Update(_ context.Context, _ *model.LDAPConnection) error       { return nil }
func (r *stubLDAPRepo) Delete(_ context.Context, _, _ string) error                   { return nil }
func (r *stubLDAPRepo) ListByTenant(_ context.Context, _ string) ([]*model.LDAPConnection, error) {
	return nil, nil
}
func (r *stubLDAPRepo) ListActiveByTenant(_ context.Context, _ string) ([]*model.LDAPConnection, error) {
	return nil, nil
}
func (r *stubLDAPRepo) List(_ context.Context) ([]*model.LDAPConnection, error) { return nil, nil }

// ---------------------------------------------------------------------------
// Stub: port.LDAPSession
// ---------------------------------------------------------------------------

type stubLDAPSession struct {
	entries    []model.LDAPEntry
	searchErr  error
	authErr    error
	lastFilter string
	authCalls  []string
}

func (s *stubLDAPSession) Authenticate(_ context.Context, userDN, _ string) error {
	s.authCalls = append(s.authCalls, userDN)
	return s.authErr
}
func (s *stubLDAPSession) Search(_ context.Context, filter string, _ []string) ([]model.LDAPEntry, error) {
	s.lastFilter = filter
	return s.entries, s.searchErr
}
func (s *stubLDAPSession) Close() error { return nil }

// Compile-time check that stubLDAPSession satisfies port.LDAPSession.
var _ port.LDAPSession = (*stubLDAPSession)(nil)

// ---------------------------------------------------------------------------
// Stub: port.LDAPDialer
// ---------------------------------------------------------------------------

type stubLDAPDialer struct {
	session port.LDAPSession
	err     error
}

func (d *stubLDAPDialer) Dial(_ context.Context, _ *model.LDAPConnection) (port.LDAPSession, error) {
	return d.session, d.err
}

// Compile-time check.
var _ port.LDAPDialer = (*stubLDAPDialer)(nil)

// ---------------------------------------------------------------------------
// Stub: port.AuditLogger — captures every Log call for assertion
// ---------------------------------------------------------------------------

type captureAuditLogger struct {
	calls []capturedAuditCall
}

type capturedAuditCall struct {
	tenantID string
	actor    string
	action   string
	details  map[string]interface{}
}

func (l *captureAuditLogger) Log(tenantID, actor, action, _, _ string, details map[string]interface{}) {
	l.calls = append(l.calls, capturedAuditCall{tenantID, actor, action, details})
}

func (l *captureAuditLogger) hasAction(action string) bool {
	for _, c := range l.calls {
		if c.action == action {
			return true
		}
	}
	return false
}

func (l *captureAuditLogger) lastWithAction(action string) (capturedAuditCall, bool) {
	for i := len(l.calls) - 1; i >= 0; i-- {
		if l.calls[i].action == action {
			return l.calls[i], true
		}
	}
	return capturedAuditCall{}, false
}

// Compile-time check.
var _ port.AuditLogger = (*captureAuditLogger)(nil)

// ---------------------------------------------------------------------------
// Helper — build the concrete use case with stub dependencies
// ---------------------------------------------------------------------------

func buildLDAPUseCase(repo *stubLDAPRepo, dialer *stubLDAPDialer, audit *captureAuditLogger) LDAPConnectionUseCase {
	return &ldapConnectionUseCase{
		repo:     repo,
		dialer:   dialer,
		audit:    audit,
		scopeUse: nil,
		outbound: nil,
	}
}

// ---------------------------------------------------------------------------
// TestAuthenticateUser — connection_not_found regression
// ---------------------------------------------------------------------------

func TestAuthenticateUser_ConnectionNotFound(t *testing.T) {
	auditLog := &captureAuditLogger{}
	repo := &stubLDAPRepo{conn: nil, err: errors.New("not found")}

	uc := buildLDAPUseCase(repo, &stubLDAPDialer{}, auditLog)
	entry, err := uc.AuthenticateUser(context.Background(), "tnt_test", "conn_missing", "alice", "pass")

	require.Error(t, err, "repo error must propagate")
	assert.Nil(t, entry)
	require.True(t, auditLog.hasAction("auth.ldap.connection.fail"),
		"auth.ldap.connection.fail must be emitted when connection lookup fails")
	call, ok := auditLog.lastWithAction("auth.ldap.connection.fail")
	require.True(t, ok)
	assert.Equal(t, "connection_not_found", call.details["reason"])
	assert.Equal(t, "conn_missing", call.details["connection_id"])
}

// ---------------------------------------------------------------------------
// TestAuthenticateUser — Gap 5
// ---------------------------------------------------------------------------

func TestAuthenticateUser_Success(t *testing.T) {
	audit := &captureAuditLogger{}
	conn := &model.LDAPConnection{TenantID: "tnt_test", UserSearchFilter: "(uid={0})"}
	repo := &stubLDAPRepo{conn: conn}
	session := &stubLDAPSession{
		entries: []model.LDAPEntry{
			{DN: "uid=alice,dc=example,dc=com", Attributes: map[string][]string{"uid": {"alice"}}},
		},
	}

	uc := buildLDAPUseCase(repo, &stubLDAPDialer{session: session}, audit)
	entry, err := uc.AuthenticateUser(context.Background(), "tnt_test", "conn_1", "alice", "correct-pw")

	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, "uid=alice,dc=example,dc=com", entry.DN)
	assert.False(t, audit.hasAction("auth.ldap.bind.fail"), "no bind.fail on success")
	assert.False(t, audit.hasAction("auth.ldap.connection.fail"), "no connection.fail on success")
}

func TestAuthenticateUser_WrongPassword(t *testing.T) {
	audit := &captureAuditLogger{}
	conn := &model.LDAPConnection{TenantID: "tnt_test", UserSearchFilter: "(uid={0})"}
	repo := &stubLDAPRepo{conn: conn}
	session := &stubLDAPSession{
		entries: []model.LDAPEntry{{DN: "uid=alice,dc=example,dc=com"}},
		authErr: errors.New("ldap: invalid credentials"),
	}

	uc := buildLDAPUseCase(repo, &stubLDAPDialer{session: session}, audit)
	entry, err := uc.AuthenticateUser(context.Background(), "tnt_test", "conn_1", "alice", "wrong-pw")

	require.Error(t, err)
	assert.Nil(t, entry)
	// Internal ldap library message must not be exposed.
	assert.Equal(t, "ldap: authentication failed", err.Error())
	require.True(t, audit.hasAction("auth.ldap.bind.fail"))
	call, _ := audit.lastWithAction("auth.ldap.bind.fail")
	assert.Equal(t, "invalid credentials", call.details["reason"])
	assert.Equal(t, "conn_1", call.details["connection_id"])
}

func TestAuthenticateUser_UserNotFound(t *testing.T) {
	audit := &captureAuditLogger{}
	conn := &model.LDAPConnection{TenantID: "tnt_test", UserSearchFilter: "(uid={0})", BaseDN: "dc=example,dc=com"}
	repo := &stubLDAPRepo{conn: conn}
	session := &stubLDAPSession{entries: []model.LDAPEntry{}} // empty — user not found

	uc := buildLDAPUseCase(repo, &stubLDAPDialer{session: session}, audit)
	entry, err := uc.AuthenticateUser(context.Background(), "tnt_test", "conn_1", "nobody", "pass")

	require.Error(t, err)
	assert.Nil(t, entry)
	require.True(t, audit.hasAction("auth.ldap.bind.fail"))
	call, _ := audit.lastWithAction("auth.ldap.bind.fail")
	assert.Equal(t, "user not found", call.details["reason"])
	require.Len(t, session.authCalls, 1)
	assert.Equal(t, "cn=__shyntr_not_found__,dc=example,dc=com", session.authCalls[0])
}

func TestAuthenticateUser_LDAPUnreachable(t *testing.T) {
	audit := &captureAuditLogger{}
	conn := &model.LDAPConnection{TenantID: "tnt_test"}
	repo := &stubLDAPRepo{conn: conn}
	dialErr := errors.New("dial tcp 10.0.0.1:389: connect: connection refused")

	uc := buildLDAPUseCase(repo, &stubLDAPDialer{err: dialErr}, audit)
	entry, err := uc.AuthenticateUser(context.Background(), "tnt_test", "conn_1", "alice", "pass")

	require.Error(t, err)
	assert.Nil(t, entry)
	require.True(t, audit.hasAction("auth.ldap.connection.fail"))
	call, _ := audit.lastWithAction("auth.ldap.connection.fail")
	assert.Equal(t, "unreachable", call.details["reason"])
}

func TestAuthenticateUser_PoolExhausted(t *testing.T) {
	audit := &captureAuditLogger{}
	conn := &model.LDAPConnection{TenantID: "tnt_test"}
	repo := &stubLDAPRepo{conn: conn}
	// Pool exhaustion is modelled as context.DeadlineExceeded with "pool" in message.
	dialErr := fmt.Errorf("ldap: connection pool full: %w", context.DeadlineExceeded)

	uc := buildLDAPUseCase(repo, &stubLDAPDialer{err: dialErr}, audit)
	entry, err := uc.AuthenticateUser(context.Background(), "tnt_test", "conn_1", "alice", "pass")

	require.Error(t, err)
	assert.Nil(t, entry)
	require.True(t, audit.hasAction("auth.ldap.connection.fail"))
	call, _ := audit.lastWithAction("auth.ldap.connection.fail")
	assert.Equal(t, "pool_exhausted", call.details["reason"])
}

func TestAuthenticateUser_FilterInjection_CannotBind(t *testing.T) {
	// An attacker supplying "alice)(uid=*" as username must not be able to
	// bypass authentication. The escaped filter must return no results or
	// a non-matching entry — the stub returns empty to simulate this.
	audit := &captureAuditLogger{}
	conn := &model.LDAPConnection{TenantID: "tnt_test", UserSearchFilter: "(uid={0})"}
	repo := &stubLDAPRepo{conn: conn}
	session := &stubLDAPSession{entries: []model.LDAPEntry{}} // no match after escaping

	uc := buildLDAPUseCase(repo, &stubLDAPDialer{session: session}, audit)
	entry, err := uc.AuthenticateUser(context.Background(), "tnt_test", "conn_1", "alice)(uid=*", "pass")

	require.Error(t, err, "injected username must not produce a successful bind")
	assert.Nil(t, entry)
	// Must emit bind.fail, not panic or succeed.
	assert.True(t, audit.hasAction("auth.ldap.bind.fail"))
	assert.Equal(t, "(uid="+ldapEscapeFilter("alice)(uid=*")+")", session.lastFilter)
	assert.NotContains(t, session.lastFilter, "alice)(uid=*")
}

// ---------------------------------------------------------------------------
// TestLDAPEscapeFilter — Gap 6
// ---------------------------------------------------------------------------

func TestLDAPEscapeFilter(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{"plain username", "alice", "alice"},
		{"username with dot", "john.doe", "john.doe"},
		{"email", "user@example.com", "user@example.com"},
		{"empty string", "", ""},
		{"asterisk", "alice*", `alice\2a`},
		{"parens", "(admin)", `\28admin\29`},
		{"backslash", `a\b`, `a\5cb`},
		{"null byte", "a\x00b", `a\00b`},
		{"slash (not special)", "a/b", "a/b"},
		{"all special chars", `*()\` + "\x00", `\2a\28\29\5c\00`},
		{"only asterisks", "***", `\2a\2a\2a`},
		{"injection attempt", "alice)(uid=*", `alice\29\28uid=\2a`},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := ldapEscapeFilter(tc.input)
			assert.Equal(t, tc.expected, got)
		})
	}
}

// ---------------------------------------------------------------------------
// TestClassifyDialError — validates audit reason categorisation
// ---------------------------------------------------------------------------

func TestClassifyDialError(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		expected string
	}{
		{"context deadline exceeded", context.DeadlineExceeded, "timeout"},
		{"context cancelled", context.Canceled, "canceled"},
		{"pool exhausted", fmt.Errorf("ldap: connection pool full: %w", context.DeadlineExceeded), "pool_exhausted"},
		{"tls error", errors.New("tls: failed to verify certificate"), "tls_error"},
		{"certificate error", errors.New("x509: certificate signed by unknown authority"), "tls_error"},
		{"connection refused", errors.New("dial tcp: connect: connection refused"), "unreachable"},
		{"generic network error", errors.New("some unknown error"), "unreachable"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := classifyDialError(tc.err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Additional stubs for management CRUD tests
// ---------------------------------------------------------------------------

// extendedStubLDAPRepo adds per-method tracking for management tests.
type extendedStubLDAPRepo struct {
	stubLDAPRepo
	created   *model.LDAPConnection
	updated   *model.LDAPConnection
	deleted   bool
	listed    []*model.LDAPConnection
	allListed []*model.LDAPConnection
	listErr   error
	createErr error
	updateErr error
	deleteErr error
}

func (r *extendedStubLDAPRepo) Create(_ context.Context, conn *model.LDAPConnection) error {
	if r.createErr != nil {
		return r.createErr
	}
	conn.ID = "generated-id"
	r.created = conn
	return nil
}
func (r *extendedStubLDAPRepo) Update(_ context.Context, conn *model.LDAPConnection) error {
	r.updated = conn
	return r.updateErr
}
func (r *extendedStubLDAPRepo) Delete(_ context.Context, _, _ string) error {
	r.deleted = true
	return r.deleteErr
}
func (r *extendedStubLDAPRepo) ListByTenant(_ context.Context, _ string) ([]*model.LDAPConnection, error) {
	return r.listed, r.listErr
}
func (r *extendedStubLDAPRepo) List(_ context.Context) ([]*model.LDAPConnection, error) {
	return r.allListed, r.listErr
}

// noopScopeUseCase satisfies ScopeUseCase with no-ops.
type noopScopeUseCase struct{}

func (n *noopScopeUseCase) CreateScope(_ context.Context, _ *model.Scope, _, _ string) (*model.Scope, error) {
	return nil, nil
}
func (n *noopScopeUseCase) GetScope(_ context.Context, _, _ string) (*model.Scope, error) {
	return nil, nil
}
func (n *noopScopeUseCase) GetScopesByNames(_ context.Context, _ string, _ []string) ([]*model.Scope, error) {
	return nil, nil
}
func (n *noopScopeUseCase) ListScopes(_ context.Context, _ string) ([]*model.Scope, error) {
	return nil, nil
}
func (n *noopScopeUseCase) UpdateScope(_ context.Context, _ *model.Scope, _, _ string) error {
	return nil
}
func (n *noopScopeUseCase) DeleteScope(_ context.Context, _, _, _, _ string) error { return nil }
func (n *noopScopeUseCase) AddClaimToScopes(_ context.Context, _ string, _ string, _ []string) error {
	return nil
}

// compile-time check
var _ ScopeUseCase = (*noopScopeUseCase)(nil)

// allowAllGuard implements port.OutboundGuard and approves every URL.
type allowAllGuard struct{}

func (g *allowAllGuard) ValidateURL(_ context.Context, _ string, _ model.OutboundTargetType, rawURL string) (*url.URL, *model.OutboundPolicy, error) {
	u, _ := url.Parse(rawURL)
	return u, nil, nil
}
func (g *allowAllGuard) NewHTTPClient(_ context.Context, _ string, _ model.OutboundTargetType, _ *model.OutboundPolicy) *http.Client {
	return http.DefaultClient
}

// compile-time check
var _ port.OutboundGuard = (*allowAllGuard)(nil)

type denyAllGuard struct {
	err error
}

func (g *denyAllGuard) ValidateURL(_ context.Context, _ string, _ model.OutboundTargetType, _ string) (*url.URL, *model.OutboundPolicy, error) {
	return nil, nil, g.err
}
func (g *denyAllGuard) NewHTTPClient(_ context.Context, _ string, _ model.OutboundTargetType, _ *model.OutboundPolicy) *http.Client {
	return http.DefaultClient
}

var _ port.OutboundGuard = (*denyAllGuard)(nil)

// buildFullLDAPUseCase constructs the concrete ldapConnectionUseCase with all deps set.
func buildFullLDAPUseCase(repo port.LDAPConnectionRepository, dialer port.LDAPDialer, al port.AuditLogger) LDAPConnectionUseCase {
	return &ldapConnectionUseCase{
		repo:     repo,
		dialer:   dialer,
		audit:    al,
		scopeUse: &noopScopeUseCase{},
		outbound: &allowAllGuard{},
	}
}

// ---------------------------------------------------------------------------
// Item 10 — LDAP management CRUD use-case tests
// ---------------------------------------------------------------------------

func TestCreateConnection_Success(t *testing.T) {
	al := &captureAuditLogger{}
	repo := &extendedStubLDAPRepo{}

	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{}, al)
	conn := &model.LDAPConnection{
		TenantID:  "tnt",
		Name:      "Corp AD",
		ServerURL: "ldap://ldap.corp.com:389",
		BaseDN:    "dc=corp,dc=com",
	}
	created, err := uc.CreateConnection(context.Background(), conn, "127.0.0.1", "test-agent")

	require.NoError(t, err)
	require.NotNil(t, created)
	assert.True(t, al.hasAction("management.connection.ldap.create"))
}

func TestCreateConnection_ValidationError(t *testing.T) {
	al := &captureAuditLogger{}
	repo := &extendedStubLDAPRepo{}
	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{}, al)

	// Missing BaseDN — Validate() should fail.
	conn := &model.LDAPConnection{
		TenantID:  "tnt",
		ServerURL: "ldap://ldap.corp.com:389",
		// BaseDN intentionally missing
	}
	_, err := uc.CreateConnection(context.Background(), conn, "", "")
	assert.Error(t, err)
}

func TestCreateConnection_DuplicateNameError(t *testing.T) {
	al := &captureAuditLogger{}
	repo := &extendedStubLDAPRepo{createErr: errors.New("duplicate ldap connection name")}
	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{}, al)

	conn := &model.LDAPConnection{
		TenantID:  "tnt",
		Name:      "Corp AD",
		ServerURL: "ldap://ldap.corp.com:389",
		BaseDN:    "dc=corp,dc=com",
	}
	_, err := uc.CreateConnection(context.Background(), conn, "", "")

	require.Error(t, err)
	assert.Equal(t, "duplicate ldap connection name", err.Error())
	assert.False(t, al.hasAction("management.connection.ldap.create"))
}

func TestCreateConnection_OutboundPolicyViolation(t *testing.T) {
	al := &captureAuditLogger{}
	repo := &extendedStubLDAPRepo{}
	uc := &ldapConnectionUseCase{
		repo:     repo,
		dialer:   &stubLDAPDialer{},
		audit:    al,
		scopeUse: &noopScopeUseCase{},
		outbound: &denyAllGuard{err: errors.New("blocked by policy")},
	}

	conn := &model.LDAPConnection{
		TenantID:  "tnt",
		Name:      "Corp AD",
		ServerURL: "ldap://ldap.corp.com:389",
		BaseDN:    "dc=corp,dc=com",
	}
	_, err := uc.CreateConnection(context.Background(), conn, "", "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "server_url violates outbound policy")
	assert.False(t, al.hasAction("management.connection.ldap.create"))
}

func TestCreateConnection_InvalidURLScheme(t *testing.T) {
	al := &captureAuditLogger{}
	repo := &extendedStubLDAPRepo{}
	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{}, al)

	conn := &model.LDAPConnection{
		TenantID:  "tnt",
		Name:      "Corp AD",
		ServerURL: "http://ldap.corp.com",
		BaseDN:    "dc=corp,dc=com",
	}
	_, err := uc.CreateConnection(context.Background(), conn, "", "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "must use ldap:// or ldaps://",
		"non-LDAP scheme must be rejected at validation time")
	assert.False(t, al.hasAction("management.connection.ldap.create"))
}

func TestCreateConnection_StartTLSWithLDAPSScheme(t *testing.T) {
	al := &captureAuditLogger{}
	repo := &extendedStubLDAPRepo{}
	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{}, al)

	conn := &model.LDAPConnection{
		TenantID:  "tnt",
		Name:      "Corp AD",
		ServerURL: "ldaps://ldap.corp.com:636",
		StartTLS:  true,
		BaseDN:    "dc=corp,dc=com",
	}
	_, err := uc.CreateConnection(context.Background(), conn, "", "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be used with ldaps://",
		"StartTLS + ldaps:// must be rejected at validation time")
	assert.False(t, al.hasAction("management.connection.ldap.create"))
}

func TestGetConnection_Success(t *testing.T) {
	existing := &model.LDAPConnection{ID: "conn-1", TenantID: "tnt", Name: "AD"}
	repo := &extendedStubLDAPRepo{stubLDAPRepo: stubLDAPRepo{conn: existing}}
	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{}, &captureAuditLogger{})

	got, err := uc.GetConnection(context.Background(), "tnt", "conn-1")
	require.NoError(t, err)
	assert.Equal(t, "conn-1", got.ID)
}

func TestGetConnection_NotFound(t *testing.T) {
	repo := &extendedStubLDAPRepo{stubLDAPRepo: stubLDAPRepo{err: errors.New("ldap connection not found")}}
	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{}, &captureAuditLogger{})

	_, err := uc.GetConnection(context.Background(), "tnt", "missing")
	assert.Error(t, err)
}

func TestGetConnection_WrongTenant(t *testing.T) {
	repo := &extendedStubLDAPRepo{stubLDAPRepo: stubLDAPRepo{err: errors.New("ldap connection not found")}}
	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{}, &captureAuditLogger{})

	_, err := uc.GetConnection(context.Background(), "other-tenant", "conn-1")
	require.Error(t, err)
	assert.Equal(t, "ldap connection not found", err.Error())
}

func TestUpdateConnection_Success(t *testing.T) {
	existing := &model.LDAPConnection{
		ID:           "conn-1",
		TenantID:     "tnt",
		Name:         "Old",
		ServerURL:    "ldap://ldap.corp.com",
		BaseDN:       "dc=corp,dc=com",
		BindPassword: "secret",
		Active:       true,
	}
	repo := &extendedStubLDAPRepo{stubLDAPRepo: stubLDAPRepo{conn: existing}}
	al := &captureAuditLogger{}
	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{}, al)

	updated := &model.LDAPConnection{
		ID:        "conn-1",
		TenantID:  "tnt",
		Name:      "New Name",
		ServerURL: "ldap://ldap.corp.com",
		BaseDN:    "dc=corp,dc=com",
	}
	err := uc.UpdateConnection(context.Background(), updated, "127.0.0.1", "agent")
	require.NoError(t, err)
	assert.True(t, al.hasAction("management.connection.ldap.update"))
}

func TestUpdateConnection_SentinelPassword(t *testing.T) {
	existing := &model.LDAPConnection{
		ID:           "conn-sentinel",
		TenantID:     "tnt",
		Name:         "AD",
		ServerURL:    "ldap://ldap.corp.com",
		BaseDN:       "dc=corp,dc=com",
		BindPassword: "original-secret",
		Active:       true,
	}
	repo := &extendedStubLDAPRepo{stubLDAPRepo: stubLDAPRepo{conn: existing}}
	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{}, &captureAuditLogger{})

	// Caller sends sentinel password — must not overwrite the existing password.
	updated := &model.LDAPConnection{
		ID:           "conn-sentinel",
		TenantID:     "tnt",
		Name:         "AD Updated",
		ServerURL:    "ldap://ldap.corp.com",
		BaseDN:       "dc=corp,dc=com",
		BindPassword: "*****",
	}
	err := uc.UpdateConnection(context.Background(), updated, "", "")
	require.NoError(t, err)
	// The repo.Update should have been called with the preserved password.
	require.NotNil(t, repo.updated)
	assert.Equal(t, "original-secret", repo.updated.BindPassword,
		"sentinel password must be replaced with the existing encrypted password")
}

func TestUpdateConnection_WrongTenant(t *testing.T) {
	repo := &extendedStubLDAPRepo{stubLDAPRepo: stubLDAPRepo{err: errors.New("ldap connection not found")}}
	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{}, &captureAuditLogger{})

	err := uc.UpdateConnection(context.Background(), &model.LDAPConnection{
		ID:        "conn-1",
		TenantID:  "other-tenant",
		Name:      "AD",
		ServerURL: "ldap://ldap.corp.com",
		BaseDN:    "dc=corp,dc=com",
	}, "", "")
	require.Error(t, err)
	assert.Equal(t, "ldap connection not found", err.Error())
}

func TestDeleteConnection_Success(t *testing.T) {
	repo := &extendedStubLDAPRepo{stubLDAPRepo: stubLDAPRepo{conn: nil}}
	al := &captureAuditLogger{}
	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{}, al)

	err := uc.DeleteConnection(context.Background(), "tnt", "conn-1", "127.0.0.1", "agent")
	require.NoError(t, err)
	assert.True(t, repo.deleted)
	assert.True(t, al.hasAction("management.connection.ldap.delete"))
}

func TestDeleteConnection_NotFound(t *testing.T) {
	repo := &extendedStubLDAPRepo{deleteErr: errors.New("ldap connection not found")}
	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{}, &captureAuditLogger{})

	err := uc.DeleteConnection(context.Background(), "tnt", "missing", "", "")
	require.Error(t, err)
	assert.Equal(t, "ldap connection not found", err.Error())
}

func TestListConnections_Success(t *testing.T) {
	conns := []*model.LDAPConnection{
		{ID: "c1", TenantID: "tnt", Name: "C1"},
		{ID: "c2", TenantID: "tnt", Name: "C2"},
	}
	repo := &extendedStubLDAPRepo{listed: conns}
	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{}, &captureAuditLogger{})

	list, err := uc.ListConnections(context.Background(), "tnt")
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestListConnections_GlobalSuccess(t *testing.T) {
	conns := []*model.LDAPConnection{
		{ID: "c1", TenantID: "tnt-a", Name: "C1"},
		{ID: "c2", TenantID: "tnt-b", Name: "C2"},
	}
	repo := &extendedStubLDAPRepo{allListed: conns}
	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{}, &captureAuditLogger{})

	list, err := uc.ListConnections(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, list, 2)
	assert.Equal(t, "tnt-a", list[0].TenantID)
	assert.Equal(t, "tnt-b", list[1].TenantID)
}

func TestTestConnection_Success(t *testing.T) {
	conn := &model.LDAPConnection{ID: "c1", TenantID: "tnt", ServerURL: "ldap://ldap.corp.com"}
	session := &stubLDAPSession{}
	repo := &extendedStubLDAPRepo{stubLDAPRepo: stubLDAPRepo{conn: conn}}
	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{session: session}, &captureAuditLogger{})

	err := uc.TestConnection(context.Background(), "tnt", "c1")
	assert.NoError(t, err)
}

func TestTestConnection_DialFailure(t *testing.T) {
	conn := &model.LDAPConnection{ID: "c1", TenantID: "tnt", ServerURL: "ldap://127.0.0.1:1"}
	repo := &extendedStubLDAPRepo{stubLDAPRepo: stubLDAPRepo{conn: conn}}
	uc := buildFullLDAPUseCase(repo, &stubLDAPDialer{err: errors.New("connection refused")}, &captureAuditLogger{})

	err := uc.TestConnection(context.Background(), "tnt", "c1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ldap test failed")
}
