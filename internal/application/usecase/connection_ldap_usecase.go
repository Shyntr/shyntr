package usecase

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	ListConnectionsByTenant(ctx context.Context, tenantID string) ([]*model.LDAPConnection, error)
	ListAllConnections(ctx context.Context) ([]*model.LDAPConnection, error)
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

func (u *ldapConnectionUseCase) ListConnectionsByTenant(ctx context.Context, tenantID string) ([]*model.LDAPConnection, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	return u.repo.ListByTenant(ctx, tenantID)
}

func (u *ldapConnectionUseCase) ListAllConnections(ctx context.Context) ([]*model.LDAPConnection, error) {
	return u.repo.List(ctx)
}

// AuthenticateUser searches for the user identified by username within the
// tenant-scoped LDAP connection, then attempts a credential bind to verify the
// password. On bind failure an audit event is emitted.
// Neither the user password nor the bind password ever appears in audit details.
func (u *ldapConnectionUseCase) AuthenticateUser(ctx context.Context, tenantID, id, username, password string) (*model.LDAPEntry, error) {
	if password == "" {
		return nil, fmt.Errorf("ldap: password cannot be empty")
	}

	conn, err := u.repo.GetByTenantAndID(ctx, tenantID, id)
	if err != nil {
		u.audit.Log(tenantID, username, "auth.ldap.connection.fail", "", "", map[string]interface{}{
			"connection_id": id,
			"reason":        "connection_not_found",
		})
		return nil, err
	}

	if !conn.Active {
		u.audit.Log(tenantID, username, "auth.ldap.connection.fail", "", "", map[string]interface{}{
			"connection_id": id,
			"reason":        "connection_inactive",
		})
		return nil, fmt.Errorf("ldap: connection is inactive")
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
		return nil, fmt.Errorf("ldap: connection failed")
	}
	defer func() { _ = session.Close() }()

	// Build the user search filter. Support both {username} and the legacy {0}
	// placeholder so stored filters from either convention work correctly.
	filter := conn.UserSearchFilter
	if filter == "" {
		filter = "(uid={0})"
	}
	escaped := ldapEscapeFilter(username)
	filter = strings.ReplaceAll(filter, "{username}", escaped)
	filter = strings.ReplaceAll(filter, "{0}", escaped)

	attrs := conn.UserSearchAttributes
	if len(attrs) == 0 {
		attrs = []string{"dn"}
	}

	// Extend the requested attribute list with every source/fallback attribute
	// referenced by attribute_mapping. LDAP only returns explicitly requested
	// attributes, so omitting them silently breaks mapped claims (e.g. mail→email).
	seen := make(map[string]bool, len(attrs))
	for _, a := range attrs {
		if a != "" {
			seen[a] = true
		}
	}
	for _, rule := range conn.AttributeMapping {
		if rule.Source != "" && !seen[rule.Source] {
			attrs = append(attrs, rule.Source)
			seen[rule.Source] = true
		}
		if rule.Fallback != "" && !seen[rule.Fallback] {
			attrs = append(attrs, rule.Fallback)
			seen[rule.Fallback] = true
		}
	}

	entries, err := session.Search(ctx, filter, attrs)
	if err != nil {
		u.audit.Log(tenantID, username, "auth.ldap.connection.fail", "", "", map[string]interface{}{
			"connection_id": id,
			"reason":        classifyDialError(err),
		})
		return nil, fmt.Errorf("ldap: search failed")
	}
	if len(entries) == 0 {
		u.audit.Log(tenantID, username, "auth.ldap.bind.fail", "", "", map[string]interface{}{
			"connection_id": id,
			"reason":        "user not found",
		})
		_ = session.Authenticate(ctx, fmt.Sprintf("cn=__shyntr_not_found__,%s", conn.BaseDN), password)
		return nil, fmt.Errorf("ldap: authentication failed")
	}
	if len(entries) > 1 {
		u.audit.Log(tenantID, username, "auth.ldap.bind.fail", "", "", map[string]interface{}{
			"connection_id": id,
			"reason":        "ambiguous_user",
		})
		return nil, fmt.Errorf("ldap: ambiguous user match")
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

// classifyDialError maps a low-level error to a stable audit reason category.
// Raw error strings from the ldap library are never exposed; only the category.
// This function is used for both dial and search errors so classification is
// consistent across the entire LDAP auth flow.
func classifyDialError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		if strings.Contains(err.Error(), "pool") {
			return "pool_exhausted"
		}
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	// net.Dialer.Timeout fires a *net.OpError where Timeout() == true.
	// This is NOT context.DeadlineExceeded, so it must be checked separately.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
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
