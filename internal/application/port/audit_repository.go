package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

type AuditLogRepository interface {
	Save(ctx context.Context, log *model.AuditLog) error
	ListByTenant(ctx context.Context, tenantID string, limit, offset int) ([]*model.AuditLog, error)
}
