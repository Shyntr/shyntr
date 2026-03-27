package usecase

import (
	"context"
	"time"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/utils"
)

type OutboundPolicyUseCase interface {
	CreatePolicy(ctx context.Context, policy *model.OutboundPolicy, actorIP, userAgent string) (*model.OutboundPolicy, error)
	UpdatePolicy(ctx context.Context, policy *model.OutboundPolicy, actorIP, userAgent string) (*model.OutboundPolicy, error)
	GetPolicy(ctx context.Context, id string) (*model.OutboundPolicy, error)
	ListPolicies(ctx context.Context, tenantID string) ([]*model.OutboundPolicy, error)
	DeletePolicy(ctx context.Context, id string, actorIP, userAgent string) error
}

type outboundPolicyUseCase struct {
	repo  port.OutboundPolicyRepository
	audit port.AuditLogger
}

func NewOutboundPolicyUseCase(repo port.OutboundPolicyRepository, audit port.AuditLogger) OutboundPolicyUseCase {
	return &outboundPolicyUseCase{
		repo:  repo,
		audit: audit,
	}
}

func (u *outboundPolicyUseCase) CreatePolicy(ctx context.Context, policy *model.OutboundPolicy, actorIP, userAgent string) (*model.OutboundPolicy, error) {
	if policy.ID == "" {
		policy.ID, _ = utils.GenerateRandomHex(8)
	}
	now := time.Now().UTC()
	policy.CreatedAt = now
	policy.UpdatedAt = now

	if err := u.repo.Create(ctx, policy); err != nil {
		return nil, err
	}

	u.audit.Log(policy.TenantID, "system", "management.outbound_policy.create", actorIP, userAgent, map[string]interface{}{
		"policy_id": policy.ID,
		"target":    policy.Target,
	})

	return policy, nil
}

func (u *outboundPolicyUseCase) UpdatePolicy(ctx context.Context, policy *model.OutboundPolicy, actorIP, userAgent string) (*model.OutboundPolicy, error) {
	policy.UpdatedAt = time.Now().UTC()

	if err := u.repo.Update(ctx, policy); err != nil {
		return nil, err
	}

	u.audit.Log(policy.TenantID, "system", "management.outbound_policy.update", actorIP, userAgent, map[string]interface{}{
		"policy_id": policy.ID,
		"target":    policy.Target,
	})

	return policy, nil
}

func (u *outboundPolicyUseCase) GetPolicy(ctx context.Context, id string) (*model.OutboundPolicy, error) {
	return u.repo.GetByID(ctx, id)
}

func (u *outboundPolicyUseCase) ListPolicies(ctx context.Context, tenantID string) ([]*model.OutboundPolicy, error) {
	return u.repo.List(ctx, tenantID)
}

func (u *outboundPolicyUseCase) DeletePolicy(ctx context.Context, id string, actorIP, userAgent string) error {
	policy, err := u.repo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if err := u.repo.Delete(ctx, id); err != nil {
		return err
	}

	u.audit.Log(policy.TenantID, "system", "management.outbound_policy.delete", actorIP, userAgent, map[string]interface{}{
		"policy_id": policy.ID,
		"target":    policy.Target,
	})

	return nil
}
