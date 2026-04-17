package usecase

import (
	"context"
	"time"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/model"
)

type HealthUseCase interface {
	CheckDatabase(ctx context.Context) error
	GetHealthSummary(ctx context.Context) (*model.HealthSummary, error)
}

type healthUseCase struct {
	repo port.HealthRepository
	km   utils.KeyManager
}

func NewHealthUseCase(repo port.HealthRepository, km utils.KeyManager) HealthUseCase {
	return &healthUseCase{
		repo: repo,
		km:   km,
	}
}

func (u *healthUseCase) CheckDatabase(ctx context.Context) error {
	return u.repo.Ping(ctx)
}

func (u *healthUseCase) GetHealthSummary(ctx context.Context) (*model.HealthSummary, error) {
	summary := &model.HealthSummary{
		Status:      "ok",
		GeneratedAt: time.Now(),
		Checks: model.HealthChecks{
			Database:    "ok",
			SigningKeys: "ok",
			Migrations:  "ok",
		},
	}

	// 1. Database Check (Critical)
	if err := u.repo.Ping(ctx); err != nil {
		summary.Checks.Database = "error"
		summary.Status = "error"
	}

	// 2. Signing Keys Check (Degraded if missing)
	_, _, errSig := u.km.GetActivePrivateKey(ctx, "sig")
	_, _, errEnc := u.km.GetActivePrivateKey(ctx, "enc")
	if errSig != nil || errEnc != nil {
		summary.Checks.SigningKeys = "degraded"
		if summary.Status == "ok" {
			summary.Status = "degraded"
		}
	}

	// 3. Migrations Check (Critical)
	if err := u.repo.VerifyMigrations(ctx); err != nil {
		summary.Checks.Migrations = "error"
		summary.Status = "error"
	}

	return summary, nil
}
