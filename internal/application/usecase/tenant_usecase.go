package usecase

import (
	"context"
	"errors"

	"github.com/nevzatcirak/shyntr/internal/adapters/http/dto"
	"github.com/nevzatcirak/shyntr/internal/application/port"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
	"github.com/nevzatcirak/shyntr/pkg/utils"
)

type TenantUseCase interface {
	CreateTenant(ctx context.Context, tenant *entity.Tenant, actorIP, userAgent string) (*entity.Tenant, error)
	GetTenant(ctx context.Context, id string) (*entity.Tenant, error)
	GetCount(ctx context.Context) (int64, error)
	GetTenantByName(ctx context.Context, name string) (*entity.Tenant, error)
	UpdateTenant(ctx context.Context, tenant *entity.Tenant, actorIP, userAgent string) error
	DeleteTenant(ctx context.Context, id string, actorIP, userAgent string) error
	ListTenants(ctx context.Context) ([]*dto.TenantResponse, error)
}

type tenantUseCase struct {
	repo  port.TenantRepository
	audit port.AuditLogger
}

func NewTenantUseCase(repo port.TenantRepository, audit port.AuditLogger) TenantUseCase {
	return &tenantUseCase{
		repo:  repo,
		audit: audit,
	}
}

func (u *tenantUseCase) CreateTenant(ctx context.Context, tenant *entity.Tenant, actorIP, userAgent string) (*entity.Tenant, error) {
	if tenant.ID == "" {
		tenant.ID, _ = utils.GenerateRandomHex(4)
	}
	if tenant.Name == "" {
		tenant.Name = tenant.ID
	}
	if tenant.DisplayName == "" {
		tenant.DisplayName = tenant.Name
	}

	if err := tenant.Validate(); err != nil {
		return nil, err
	}

	if err := u.repo.Create(ctx, tenant); err != nil {
		return nil, err
	}

	u.audit.Log(tenant.ID, "system", "management.tenant.create", actorIP, userAgent, map[string]interface{}{
		"tenant_name": tenant.Name,
	})

	return tenant, nil
}

func (u *tenantUseCase) GetTenant(ctx context.Context, id string) (*entity.Tenant, error) {
	return u.repo.GetByID(ctx, id)
}

func (u *tenantUseCase) GetCount(ctx context.Context) (int64, error) {
	return u.repo.GetCount(ctx)
}

func (u *tenantUseCase) GetTenantByName(ctx context.Context, name string) (*entity.Tenant, error) {
	return u.repo.GetByName(ctx, name)
}

func (u *tenantUseCase) UpdateTenant(ctx context.Context, tenant *entity.Tenant, actorIP, userAgent string) error {
	if err := u.repo.Update(ctx, tenant); err != nil {
		return err
	}

	u.audit.Log(tenant.ID, "system", "management.tenant.update", actorIP, userAgent, map[string]interface{}{
		"tenant_id": tenant.ID,
	})
	return nil
}

func (u *tenantUseCase) DeleteTenant(ctx context.Context, id string, actorIP, userAgent string) error {
	if id == "default" {
		return errors.New("cannot delete the default tenant")
	}

	if err := u.repo.CascadeDelete(ctx, id); err != nil {
		return err
	}

	u.audit.Log(id, "system", "management.tenant.delete", actorIP, userAgent, map[string]interface{}{
		"tenant_id": id,
	})

	return nil
}

func (u *tenantUseCase) ListTenants(ctx context.Context) ([]*dto.TenantResponse, error) {
	tenants, err := u.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	return dto.FromDomainTenants(tenants), nil
}
