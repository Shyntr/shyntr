package port

import (
	"context"
	"time"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

type AuditLogRepository interface {
	Save(ctx context.Context, log *model.AuditLog) error
	ListByTenant(ctx context.Context, tenantID string, limit, offset int) ([]*model.AuditLog, error)
	GetAuthActivityCounts(ctx context.Context, since time.Time) (counts map[string]map[string]int64, totalSuccess int64, totalFailure int64, err error)
}
