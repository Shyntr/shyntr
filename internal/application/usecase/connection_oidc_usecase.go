package usecase

import (
	"context"
	"fmt"

	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
)

type OIDCConnectionUseCase interface {
	CreateConnection(ctx context.Context, conn *model.OIDCConnection, actorIP, userAgent string) (*model.OIDCConnection, error)
	UpdateConnection(ctx context.Context, conn *model.OIDCConnection, actorIP, userAgent string) error
	GetConnection(ctx context.Context, tenantID, id string) (*model.OIDCConnection, error)
	GetConnectionCount(ctx context.Context, tenantID string) (int64, error)
	DeleteConnection(ctx context.Context, tenantID, id string, actorIP, userAgent string) error
	ListConnectionsByTenant(ctx context.Context, tenantID string) ([]*model.OIDCConnection, error)
	ListAllConnections(ctx context.Context) ([]*model.OIDCConnection, error)
	bindMappingScopes(ctx context.Context, tenantID string, mappings map[string]model.AttributeMappingRule)
}

type oidcConnectionUseCase struct {
	repo     port.OIDCConnectionRepository
	audit    port.AuditLogger
	scopeUse ScopeUseCase
	outbound port.OutboundGuard
}

func NewOIDCConnectionUseCase(repo port.OIDCConnectionRepository, audit port.AuditLogger, scopeUse ScopeUseCase, guard port.OutboundGuard) OIDCConnectionUseCase {
	return &oidcConnectionUseCase{repo: repo, audit: audit, scopeUse: scopeUse, outbound: guard}
}

func (u *oidcConnectionUseCase) bindMappingScopes(ctx context.Context, tenantID string, mappings map[string]model.AttributeMappingRule) {
	for _, rule := range mappings {
		if len(rule.TargetScopes) > 0 && rule.Target != "" {
			err := u.scopeUse.AddClaimToScopes(ctx, tenantID, rule.Target, rule.TargetScopes)
			if err != nil {
				logger.Log.Warn("Failed to auto-bind claim to scopes during connection save",
					zap.String("tenant_id", tenantID),
					zap.String("claim", rule.Target),
					zap.Error(err),
				)
			}
		}
	}
}

func (u *oidcConnectionUseCase) validateOutboundEndpoints(ctx context.Context, conn *model.OIDCConnection) error {
	if conn.IssuerURL != "" {
		if _, _, err := u.outbound.ValidateURL(ctx, conn.TenantID, model.OutboundTargetOIDCDiscovery, conn.IssuerURL); err != nil {
			return fmt.Errorf("issuer_url violates outbound policy: %w", err)
		}
	}

	for field, endpoint := range map[string]string{
		"authorization_endpoint": conn.AuthorizationEndpoint,
		"token_endpoint":         conn.TokenEndpoint,
		"userinfo_endpoint":      conn.UserInfoEndpoint,
		"jwks_uri":               conn.JWKSURI,
		"end_session_endpoint":   conn.EndSessionEndpoint,
	} {
		if endpoint == "" {
			continue
		}

		target := model.OutboundTargetOIDCDiscovery
		if field == "end_session_endpoint" {
			target = model.OutboundTargetOIDCBackchannel
		}

		if _, _, err := u.outbound.ValidateURL(ctx, conn.TenantID, target, endpoint); err != nil {
			return fmt.Errorf("%s violates outbound policy: %w", field, err)
		}
	}

	return nil
}

func (u *oidcConnectionUseCase) CreateConnection(ctx context.Context, conn *model.OIDCConnection, actorIP, userAgent string) (*model.OIDCConnection, error) {
	if conn.ID == "" {
		conn.ID = uuid.New().String()
	}
	if len(conn.Scopes) == 0 {
		conn.Scopes = []string{"openid", "profile", "email"}
	}
	conn.Active = true

	if err := conn.Validate(); err != nil {
		return nil, err
	}
	if err := u.validateOutboundEndpoints(ctx, conn); err != nil {
		return nil, err
	}

	if err := u.repo.Create(ctx, conn); err != nil {
		return nil, err
	}

	u.bindMappingScopes(ctx, conn.TenantID, conn.AttributeMapping)
	u.audit.Log(conn.TenantID, "system", "management.connection.oidc.create", actorIP, userAgent, map[string]interface{}{
		"connection_id": conn.ID,
		"issuer_url":    conn.IssuerURL,
		"name":          conn.Name,
		"scopes":        conn.Scopes,
	})

	return conn, nil
}

func (u *oidcConnectionUseCase) UpdateConnection(ctx context.Context, conn *model.OIDCConnection, actorIP, userAgent string) error {
	connection, err := u.GetConnection(ctx, conn.TenantID, conn.ID)
	if err != nil {
		return err
	}
	if len(conn.Scopes) == 0 {
		conn.Scopes = []string{"openid", "profile", "email"}
	}
	conn.Active = connection.Active

	if err := conn.Validate(); err != nil {
		return err
	}
	if err := u.validateOutboundEndpoints(ctx, conn); err != nil {
		return err
	}

	if err := u.repo.Update(ctx, conn); err != nil {
		return err
	}

	u.bindMappingScopes(ctx, conn.TenantID, conn.AttributeMapping)
	u.audit.Log(conn.TenantID, "system", "management.connection.oidc.update", actorIP, userAgent, map[string]interface{}{
		"connection_id": conn.ID,
		"issuer_url":    conn.IssuerURL,
		"name":          conn.Name,
		"scopes":        conn.Scopes,
	})

	return nil
}

func (u *oidcConnectionUseCase) GetConnection(ctx context.Context, tenantID, id string) (*model.OIDCConnection, error) {
	return u.repo.GetByTenantAndID(ctx, tenantID, id)
}

func (u *oidcConnectionUseCase) GetConnectionCount(ctx context.Context, tenantID string) (int64, error) {
	return u.repo.GetConnectionCount(ctx, tenantID)
}

func (u *oidcConnectionUseCase) DeleteConnection(ctx context.Context, tenantID, id string, actorIP, userAgent string) error {
	if err := u.repo.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	u.audit.Log(tenantID, "system", "management.connection.oidc.delete", actorIP, userAgent, map[string]interface{}{"connection_id": id})
	return nil
}

func (u *oidcConnectionUseCase) ListConnectionsByTenant(ctx context.Context, tenantID string) ([]*model.OIDCConnection, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	return u.repo.ListByTenant(ctx, tenantID)
}

func (u *oidcConnectionUseCase) ListAllConnections(ctx context.Context) ([]*model.OIDCConnection, error) {
	return u.repo.List(ctx)
}
