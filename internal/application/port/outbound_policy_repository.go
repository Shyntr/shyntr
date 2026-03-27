package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

type OutboundPolicyRepository interface {
	GetEffectivePolicy(ctx context.Context, tenantID string, target model.OutboundTargetType) (*model.OutboundPolicy, error)
	GetByID(ctx context.Context, id string) (*model.OutboundPolicy, error)
	List(ctx context.Context, tenantID string) ([]*model.OutboundPolicy, error)
	Create(ctx context.Context, policy *model.OutboundPolicy) error
	Update(ctx context.Context, policy *model.OutboundPolicy) error
	Delete(ctx context.Context, id string) error
}
