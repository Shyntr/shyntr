package port

import "context"

type HealthRepository interface {
	Ping(ctx context.Context) error
	VerifyMigrations(ctx context.Context) error
}
