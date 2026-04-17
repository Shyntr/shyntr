package usecase

// Internal test file (package usecase, not usecase_test) to allow testing
// unexported helpers (ldapEscapeFilter, classifyDialError) alongside the
// public AuthenticateUser method.

import (
	"context"
	"errors"
	"fmt"
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
	entries   []model.LDAPEntry
	searchErr error
	authErr   error
}

func (s *stubLDAPSession) Authenticate(_ context.Context, _, _ string) error { return s.authErr }
func (s *stubLDAPSession) Search(_ context.Context, _ string, _ []string) ([]model.LDAPEntry, error) {
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
	conn := &model.LDAPConnection{TenantID: "tnt_test", UserSearchFilter: "(uid={0})"}
	repo := &stubLDAPRepo{conn: conn}
	session := &stubLDAPSession{entries: []model.LDAPEntry{}} // empty — user not found

	uc := buildLDAPUseCase(repo, &stubLDAPDialer{session: session}, audit)
	entry, err := uc.AuthenticateUser(context.Background(), "tnt_test", "conn_1", "nobody", "pass")

	require.Error(t, err)
	assert.Nil(t, entry)
	require.True(t, audit.hasAction("auth.ldap.bind.fail"))
	call, _ := audit.lastWithAction("auth.ldap.bind.fail")
	assert.Equal(t, "user not found", call.details["reason"])
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
		{"context cancelled", context.Canceled, "timeout"},
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
