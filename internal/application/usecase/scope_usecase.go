package usecase

import (
	"context"
	"errors"
	"strings"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/google/uuid"
)

type ScopeUseCase interface {
	CreateScope(ctx context.Context, scope *model.Scope, actorIP, userAgent string) (*model.Scope, error)
	GetScope(ctx context.Context, tenantID, id string) (*model.Scope, error)
	GetScopesByNames(ctx context.Context, tenantID string, names []string) ([]*model.Scope, error)
	ListScopes(ctx context.Context, tenantID string) ([]*model.Scope, error)
	UpdateScope(ctx context.Context, scope *model.Scope, actorIP, userAgent string) error
	DeleteScope(ctx context.Context, tenantID, id string, actorIP, userAgent string) error
	AddClaimToScopes(ctx context.Context, tenantID string, claim string, scopeNames []string) error
}

type scopeUseCase struct {
	repo  port.ScopeRepository
	audit port.AuditLogger
}

func NewScopeUseCase(repo port.ScopeRepository, audit port.AuditLogger) ScopeUseCase {
	return &scopeUseCase{
		repo:  repo,
		audit: audit,
	}
}

func (u *scopeUseCase) CreateScope(ctx context.Context, scope *model.Scope, actorIP, userAgent string) (*model.Scope, error) {
	scope.Name = strings.ToLower(strings.TrimSpace(scope.Name))
	scope.IsSystem = false

	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if scope.ID == "" {
		scope.ID = uuid.New().String()
	}

	existing, err := u.repo.GetByName(ctx, scope.TenantID, scope.Name)
	if err == nil && existing != nil {
		return nil, errors.New("conflict: a scope with this name already exists")
	}

	if err := u.repo.Create(ctx, scope); err != nil {
		return nil, err
	}

	u.audit.Log(scope.TenantID, "system", "management.scope.create", actorIP, userAgent, map[string]interface{}{
		"scope_id":   scope.ID,
		"scope_name": scope.Name,
	})

	return scope, nil
}

func (u *scopeUseCase) GetScope(ctx context.Context, tenantID, id string) (*model.Scope, error) {
	return u.repo.GetByID(ctx, tenantID, id)
}

func (u *scopeUseCase) GetScopesByNames(ctx context.Context, tenantID string, names []string) ([]*model.Scope, error) {
	allScopes, err := u.repo.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	var result []*model.Scope
	nameMap := make(map[string]bool)
	for _, n := range names {
		nameMap[n] = true
	}

	for _, s := range allScopes {
		if nameMap[s.Name] {
			result = append(result, s)
		}
	}
	return result, nil
}

func (u *scopeUseCase) ListScopes(ctx context.Context, tenantID string) ([]*model.Scope, error) {
	return u.repo.ListByTenant(ctx, tenantID)
}

func (u *scopeUseCase) UpdateScope(ctx context.Context, scope *model.Scope, actorIP, userAgent string) error {
	existing, err := u.repo.GetByID(ctx, scope.TenantID, scope.ID)
	if err != nil {
		return err
	}

	scope.IsSystem = existing.IsSystem
	if existing.IsSystem && existing.Name != scope.Name {
		return errors.New("security_violation: cannot rename a system-level scope")
	}
	if existing.Name != scope.Name {
		conflict, err := u.repo.GetByName(ctx, scope.TenantID, scope.Name)
		if err == nil && conflict != nil {
			return errors.New("conflict: a scope with this name already exists")
		}
	}

	if err := u.repo.Update(ctx, scope); err != nil {
		return err
	}

	u.audit.Log(scope.TenantID, "system", "management.scope.update", actorIP, userAgent, map[string]interface{}{
		"scope_id":   scope.ID,
		"scope_name": scope.Name,
	})

	return nil
}

func (u *scopeUseCase) DeleteScope(ctx context.Context, tenantID, id string, actorIP, userAgent string) error {
	scope, err := u.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return err
	}

	if scope.IsSystem {
		u.audit.Log(tenantID, "system", "management.scope.delete_failed_system_scope", actorIP, userAgent, map[string]interface{}{
			"scope_id":   id,
			"scope_name": scope.Name,
		})
		return errors.New("security_violation: cannot delete a system-level scope")
	}

	if err := u.repo.Delete(ctx, tenantID, id); err != nil {
		return err
	}

	u.audit.Log(tenantID, "system", "management.scope.delete", actorIP, userAgent, map[string]interface{}{
		"scope_id": id,
	})
	return nil
}

func (u *scopeUseCase) AddClaimToScopes(ctx context.Context, tenantID string, claim string, scopeNames []string) error {
	if len(scopeNames) == 0 || claim == "" {
		return nil
	}

	scopes, err := u.GetScopesByNames(ctx, tenantID, scopeNames)
	if err != nil {
		return err
	}

	for _, scope := range scopes {
		if !containsString(scope.Claims, claim) {
			scope.Claims = append(scope.Claims, claim)
			if err := u.repo.Update(ctx, scope); err != nil {
				return err
			}
			u.audit.Log(tenantID, "system", "management.scope.auto_claim_bind", "system", "backend", map[string]interface{}{
				"scope_name":  scope.Name,
				"added_claim": claim,
			})
		}
	}
	return nil
}

func containsString(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
