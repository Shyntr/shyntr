package usecase

import (
	"context"

	"github.com/nevzatcirak/shyntr/internal/application/port"
)

type HealthUseCase interface {
	CheckDatabase(ctx context.Context) error
}

type healthUseCase struct {
	repo port.HealthRepository
}

func NewHealthUseCase(repo port.HealthRepository) HealthUseCase {
	return &healthUseCase{
		repo: repo,
	}
}

func (u *healthUseCase) CheckDatabase(ctx context.Context) error {
	return u.repo.Ping(ctx)
}
