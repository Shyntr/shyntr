package usecase

import (
	"context"
	"time"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
)

type AuditUseCase interface {
	GetTenantLogs(ctx context.Context, tenantID string, limit, offset int) ([]*model.AuditLog, error)
	GetAuthActivity(ctx context.Context, timeRange string) (*model.AuthActivity, error)
	GetAuthFailures(ctx context.Context, timeRange string) (*model.AuthFailures, error)
	GetRoutingInsights(ctx context.Context, timeRange string) (*model.RoutingInsights, error)
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

func (u *auditUseCase) GetAuthActivity(ctx context.Context, timeRange string) (*model.AuthActivity, error) {
	var since time.Time
	now := time.Now()

	switch timeRange {
	case "1h":
		since = now.Add(-1 * time.Hour)
	case "24h":
		since = now.Add(-24 * time.Hour)
	case "7d":
		since = now.Add(-7 * 24 * time.Hour)
	default:
		// Default to 24h if invalid range
		timeRange = "24h"
		since = now.Add(-24 * time.Hour)
	}

	counts, totalSuccess, totalFailure, err := u.repo.GetAuthActivityCounts(ctx, since)
	if err != nil {
		return nil, err
	}

	activity := &model.AuthActivity{
		Range:       timeRange,
		GeneratedAt: now,
		Protocols:   make(map[string]model.AuthActivityOutcome),
		Totals: model.AuthActivityOutcome{
			Success: totalSuccess,
			Failure: totalFailure,
		},
	}

	for proto, outcomes := range counts {
		outcome := model.AuthActivityOutcome{
			Success: outcomes["success"],
			Failure: outcomes["failure"],
		}
		activity.Protocols[proto] = outcome
	}

	return activity, nil
}

func (u *auditUseCase) GetAuthFailures(ctx context.Context, timeRange string) (*model.AuthFailures, error) {
	var since time.Time
	now := time.Now()

	switch timeRange {
	case "1h":
		since = now.Add(-1 * time.Hour)
	case "24h":
		since = now.Add(-24 * time.Hour)
	case "7d":
		since = now.Add(-7 * 24 * time.Hour)
	default:
		timeRange = "24h"
		since = now.Add(-24 * time.Hour)
	}

	metrics, err := u.repo.GetAuthFailureMetrics(ctx, since)
	if err != nil {
		return nil, err
	}

	metrics.Range = timeRange
	return metrics, nil
}

func (u *auditUseCase) GetRoutingInsights(ctx context.Context, timeRange string) (*model.RoutingInsights, error) {
	var since time.Time
	now := time.Now()

	switch timeRange {
	case "1h":
		since = now.Add(-1 * time.Hour)
	case "24h":
		since = now.Add(-24 * time.Hour)
	case "7d":
		since = now.Add(-7 * 24 * time.Hour)
	default:
		timeRange = "24h"
		since = now.Add(-24 * time.Hour)
	}

	insights, err := u.repo.GetRoutingInsights(ctx, since)
	if err != nil {
		return nil, err
	}

	insights.Range = timeRange
	return insights, nil
}
