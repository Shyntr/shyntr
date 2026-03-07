package port

import (
	"context"

	"github.com/nevzatcirak/shyntr/internal/domain/entity"
)

type AuditLogRepository interface {
	Save(ctx context.Context, log *entity.AuditLog) error
	ListByTenant(ctx context.Context, tenantID string, limit, offset int) ([]*entity.AuditLog, error)
}
