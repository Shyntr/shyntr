package usecase

import (
	"context"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
)

type AuditUseCase interface {
	GetTenantLogs(ctx context.Context, tenantID string, limit, offset int) ([]*model.AuditLog, error)
}

type auditUseCase struct {
	repo port.AuditLogRepository
}

func NewAuditUseCase(repo port.AuditLogRepository) AuditUseCase {
	return &auditUseCase{repo: repo}
}

func (u *auditUseCase) GetTenantLogs(ctx context.Context, tenantID string, limit, offset int) ([]*model.AuditLog, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	return u.repo.ListByTenant(ctx, tenantID, limit, offset)
}
