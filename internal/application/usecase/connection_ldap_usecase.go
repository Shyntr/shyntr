package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
)

// LDAPConnectionUseCase manages LDAP/Active-Directory identity-provider connections.
type LDAPConnectionUseCase interface {
	CreateConnection(ctx context.Context, conn *model.LDAPConnection, actorIP, userAgent string) (*model.LDAPConnection, error)
	GetConnection(ctx context.Context, tenantID, id string) (*model.LDAPConnection, error)
	GetConnectionCount(ctx context.Context, tenantID string) (int64, error)
	TestConnection(ctx context.Context, tenantID, id string) error
	UpdateConnection(ctx context.Context, conn *model.LDAPConnection, actorIP, userAgent string) error
	DeleteConnection(ctx context.Context, tenantID, id string, actorIP, userAgent string) error
	ListConnections(ctx context.Context, tenantID string) ([]*model.LDAPConnection, error)
	AuthenticateUser(ctx context.Context, tenantID, id, username, password string) (*model.LDAPEntry, error)
	bindMappingScopes(ctx context.Context, tenantID string, mappings map[string]model.AttributeMappingRule)
}

type ldapConnectionUseCase struct {
	repo     port.LDAPConnectionRepository
	dialer   port.LDAPDialer
	audit    port.AuditLogger
	scopeUse ScopeUseCase
	outbound port.OutboundGuard
}

func NewLDAPConnectionUseCase(
	repo port.LDAPConnectionRepository,
	dialer port.LDAPDialer,
	audit port.AuditLogger,
	scopeUse ScopeUseCase,
	outbound port.OutboundGuard,
) LDAPConnectionUseCase {
	return &ldapConnectionUseCase{
		repo:     repo,
		dialer:   dialer,
		audit:    audit,
		scopeUse: scopeUse,
		outbound: outbound,
	}
}

func (u *ldapConnectionUseCase) bindMappingScopes(ctx context.Context, tenantID string, mappings map[string]model.AttributeMappingRule) {
	for _, rule := range mappings {
		if len(rule.TargetScopes) > 0 && rule.Target != "" {
			if err := u.scopeUse.AddClaimToScopes(ctx, tenantID, rule.Target, rule.TargetScopes); err != nil {
				logger.Log.Warn("Failed to auto-bind claim to scopes during LDAP connection save",
					zap.String("tenant_id", tenantID),
					zap.String("claim", rule.Target),
					zap.Error(err),
				)
			}
		}
	}
}

func (u *ldapConnectionUseCase) CreateConnection(ctx context.Context, conn *model.LDAPConnection, actorIP, userAgent string) (*model.LDAPConnection, error) {
	if conn.ID == "" {
		conn.ID = uuid.New().String()
	}

	if _, _, err := u.outbound.ValidateURL(ctx, conn.TenantID, model.OutboundTargetLDAPAuth, conn.ServerURL); err != nil {
		return nil, fmt.Errorf("server_url violates outbound policy: %w", err)
	}

	conn.Active = true

	if err := conn.Validate(); err != nil {
		return nil, err
	}

	if err := u.repo.Create(ctx, conn); err != nil {
		return nil, err
	}

	u.bindMappingScopes(ctx, conn.TenantID, conn.AttributeMapping)
	u.audit.Log(conn.TenantID, "system", "management.connection.ldap.create", actorIP, userAgent, map[string]interface{}{
		"connection_id": conn.ID,
		"server_url":    conn.ServerURL,
		"name":          conn.Name,
		"bind_dn":       conn.BindDN,
	})

	return conn, nil
}

func (u *ldapConnectionUseCase) GetConnection(ctx context.Context, tenantID, id string) (*model.LDAPConnection, error) {
	return u.repo.GetByTenantAndID(ctx, tenantID, id)
}

func (u *ldapConnectionUseCase) GetConnectionCount(ctx context.Context, tenantID string) (int64, error) {
	return u.repo.GetConnectionCount(ctx, tenantID)
}

// TestConnection dials the LDAP server using the stored connection config to
// verify connectivity and service-account credentials. It is tenant-scoped:
// a connection belonging to one tenant cannot be tested via another tenant's ID.
func (u *ldapConnectionUseCase) TestConnection(ctx context.Context, tenantID, id string) error {
	conn, err := u.repo.GetByTenantAndID(ctx, tenantID, id)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	session, err := u.dialer.Dial(ctx, conn)
	if err != nil {
		return fmt.Errorf("ldap test failed: %w", err)
	}
	return session.Close()
}

func (u *ldapConnectionUseCase) UpdateConnection(ctx context.Context, conn *model.LDAPConnection, actorIP, userAgent string) error {
	// Enforce tenant ownership before update.
	existing, err := u.GetConnection(ctx, conn.TenantID, conn.ID)
	if err != nil {
		return err
	}

	// If caller did not supply a new password keep the persisted one.
	if conn.BindPassword == "" || conn.BindPassword == "*****" {
		conn.BindPassword = existing.BindPassword
	}

	if conn.ServerURL != existing.ServerURL {
		if _, _, err := u.outbound.ValidateURL(ctx, conn.TenantID, model.OutboundTargetLDAPAuth, conn.ServerURL); err != nil {
			return fmt.Errorf("server_url violates outbound policy: %w", err)
		}
	}

	conn.Active = existing.Active

	if err := conn.Validate(); err != nil {
		return err
	}

	if err := u.repo.Update(ctx, conn); err != nil {
		return err
	}

	u.bindMappingScopes(ctx, conn.TenantID, conn.AttributeMapping)
	u.audit.Log(conn.TenantID, "system", "management.connection.ldap.update", actorIP, userAgent, map[string]interface{}{
		"connection_id": conn.ID,
		"server_url":    conn.ServerURL,
		"name":          conn.Name,
		"bind_dn":       conn.BindDN,
	})

	return nil
}

func (u *ldapConnectionUseCase) DeleteConnection(ctx context.Context, tenantID, id string, actorIP, userAgent string) error {
	if err := u.repo.Delete(ctx, tenantID, id); err != nil {
		return err
	}

	u.audit.Log(tenantID, "system", "management.connection.ldap.delete", actorIP, userAgent, map[string]interface{}{
		"connection_id": id,
	})

	return nil
}

func (u *ldapConnectionUseCase) ListConnections(ctx context.Context, tenantID string) ([]*model.LDAPConnection, error) {
	if tenantID == "" {
		return u.repo.List(ctx)
	}
	return u.repo.ListByTenant(ctx, tenantID)
}

// AuthenticateUser searches for the user identified by username within the
// tenant-scoped LDAP connection, then attempts a credential bind to verify the
// password. On bind failure an audit event is emitted.
// Neither the user password nor the bind password ever appears in audit details.
func (u *ldapConnectionUseCase) AuthenticateUser(ctx context.Context, tenantID, id, username, password string) (*model.LDAPEntry, error) {
	conn, err := u.repo.GetByTenantAndID(ctx, tenantID, id)
	if err != nil {
		u.audit.Log(tenantID, username, "auth.ldap.connection.fail", "", "", map[string]interface{}{
			"connection_id": id,
			"reason":        "connection_not_found",
		})
		return nil, err
	}

	// Bound the outbound LDAP operation so a hung server cannot hold the
	// Gin handler goroutine for the full HTTP server write timeout.
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	session, err := u.dialer.Dial(ctx, conn)
	if err != nil {
		u.audit.Log(tenantID, username, "auth.ldap.connection.fail", "", "", map[string]interface{}{
			"connection_id": id,
			"reason":        classifyDialError(err),
		})
		return nil, fmt.Errorf("ldap: failed to open session: %w", err)
	}
	defer func() { _ = session.Close() }()

	// Build the user search filter by substituting {0} with the sanitised username.
	filter := conn.UserSearchFilter
	if filter == "" {
		filter = "(uid={0})"
	}
	filter = strings.ReplaceAll(filter, "{0}", ldapEscapeFilter(username))

	attrs := conn.UserSearchAttributes
	if len(attrs) == 0 {
		attrs = []string{"dn"}
	}

	entries, err := session.Search(ctx, filter, attrs)
	if err != nil {
		u.audit.Log(tenantID, username, "auth.ldap.connection.fail", "", "", map[string]interface{}{
			"connection_id": id,
			"reason":        "unreachable",
		})
		return nil, fmt.Errorf("ldap: user search failed: %w", err)
	}
	if len(entries) == 0 {
		u.audit.Log(tenantID, username, "auth.ldap.bind.fail", "", "", map[string]interface{}{
			"connection_id": id,
			"reason":        "user not found",
		})
		_ = session.Authenticate(ctx, fmt.Sprintf("cn=__shyntr_not_found__,%s", conn.BaseDN), password)
		return nil, fmt.Errorf("ldap: authentication failed")
	}

	userDN := entries[0].DN
	if err := session.Authenticate(ctx, userDN, password); err != nil {
		u.audit.Log(tenantID, username, "auth.ldap.bind.fail", "", "", map[string]interface{}{
			"connection_id": id,
			"reason":        "invalid credentials",
		})
		return nil, fmt.Errorf("ldap: authentication failed")
	}

	return &entries[0], nil
}

// classifyDialError maps a low-level dial error to a stable audit reason category.
// Raw error strings from the ldap library are never exposed; only the category.
func classifyDialError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		msg := err.Error()
		if strings.Contains(msg, "pool") {
			return "pool_exhausted"
		}
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "tls") || strings.Contains(msg, "certificate") || strings.Contains(msg, "x509") {
		return "tls_error"
	}
	return "unreachable"
}

// ldapEscapeFilter escapes special characters in an LDAP search filter value
// per RFC 4515 to prevent filter-injection attacks.
func ldapEscapeFilter(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\5c`,
		`*`, `\2a`,
		`(`, `\28`,
		`)`, `\29`,
		"\x00", `\00`,
	)
	return replacer.Replace(s)
}
