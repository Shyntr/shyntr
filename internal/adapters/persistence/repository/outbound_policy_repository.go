package repository

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"gorm.io/gorm"
)

type outboundPolicyRepository struct {
	db *gorm.DB
}

func NewOutboundPolicyRepository(db *gorm.DB) port.OutboundPolicyRepository {
	return &outboundPolicyRepository{db: db}
}

func (r *outboundPolicyRepository) GetEffectivePolicy(ctx context.Context, tenantID string, target model.OutboundTargetType) (*model.OutboundPolicy, error) {
	var row models.OutboundPolicyGORM

	if tenantID != "" {
		err := r.db.WithContext(ctx).
			Where("tenant_id = ? AND target = ? AND enabled = ?", tenantID, string(target), true).
			First(&row).Error
		if err == nil {
			return toDomainOutboundPolicy(&row)
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	}

	err := r.db.WithContext(ctx).
		Where("(tenant_id = '' OR tenant_id IS NULL) AND target = ? AND enabled = ?", string(target), true).
		First(&row).Error
	if err != nil {
		return nil, err
	}

	return toDomainOutboundPolicy(&row)
}

func (r *outboundPolicyRepository) GetByID(ctx context.Context, id string) (*model.OutboundPolicy, error) {
	var row models.OutboundPolicyGORM
	if err := r.db.WithContext(ctx).First(&row, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return toDomainOutboundPolicy(&row)
}

func (r *outboundPolicyRepository) List(ctx context.Context, tenantID string) ([]*model.OutboundPolicy, error) {
	var rows []models.OutboundPolicyGORM
	q := r.db.WithContext(ctx)
	if tenantID != "" {
		q = q.Where("tenant_id = ? OR tenant_id = '' OR tenant_id IS NULL", tenantID)
	}
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}

	out := make([]*model.OutboundPolicy, 0, len(rows))
	for i := range rows {
		item, err := toDomainOutboundPolicy(&rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

func (r *outboundPolicyRepository) Create(ctx context.Context, policy *model.OutboundPolicy) error {
	row, err := toGORMOutboundPolicy(policy)
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).Create(row).Error
}

func (r *outboundPolicyRepository) Update(ctx context.Context, policy *model.OutboundPolicy) error {
	row, err := toGORMOutboundPolicy(policy)
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).Model(&models.OutboundPolicyGORM{}).Where("id = ?", row.ID).Updates(row).Error
}

func (r *outboundPolicyRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&models.OutboundPolicyGORM{}, "id = ?", id).Error
}

func toDomainOutboundPolicy(row *models.OutboundPolicyGORM) (*model.OutboundPolicy, error) {
	var schemes []string
	var hosts []string
	var paths []string
	var ports []int

	if row.AllowedSchemesJSON != "" {
		if err := json.Unmarshal([]byte(row.AllowedSchemesJSON), &schemes); err != nil {
			return nil, err
		}
	}
	if row.AllowedHostPatternsJSON != "" {
		if err := json.Unmarshal([]byte(row.AllowedHostPatternsJSON), &hosts); err != nil {
			return nil, err
		}
	}
	if row.AllowedPathPatternsJSON != "" {
		if err := json.Unmarshal([]byte(row.AllowedPathPatternsJSON), &paths); err != nil {
			return nil, err
		}
	}
	if row.AllowedPortsJSON != "" {
		if err := json.Unmarshal([]byte(row.AllowedPortsJSON), &ports); err != nil {
			return nil, err
		}
	}

	return &model.OutboundPolicy{
		ID:                    row.ID,
		TenantID:              row.TenantID,
		Name:                  row.Name,
		Target:                model.OutboundTargetType(row.Target),
		Enabled:               row.Enabled,
		AllowedSchemes:        schemes,
		AllowedHostPatterns:   hosts,
		AllowedPathPatterns:   paths,
		AllowedPorts:          ports,
		BlockPrivateIPs:       row.BlockPrivateIPs,
		BlockLoopbackIPs:      row.BlockLoopbackIPs,
		BlockLinkLocalIPs:     row.BlockLinkLocalIPs,
		BlockMulticastIPs:     row.BlockMulticastIPs,
		BlockLocalhostNames:   row.BlockLocalhostNames,
		DisableRedirects:      row.DisableRedirects,
		RequireDNSResolve:     row.RequireDNSResolve,
		RequestTimeoutSeconds: int(row.RequestTimeoutSeconds),
		MaxResponseBytes:      row.MaxResponseBytes,
		CreatedAt:             row.CreatedAt,
		UpdatedAt:             row.UpdatedAt,
	}, nil
}

func toGORMOutboundPolicy(policy *model.OutboundPolicy) (*models.OutboundPolicyGORM, error) {
	schemesJSON, err := json.Marshal(policy.AllowedSchemes)
	if err != nil {
		return nil, err
	}
	hostsJSON, err := json.Marshal(policy.AllowedHostPatterns)
	if err != nil {
		return nil, err
	}
	pathsJSON, err := json.Marshal(policy.AllowedPathPatterns)
	if err != nil {
		return nil, err
	}
	portsJSON, err := json.Marshal(policy.AllowedPorts)
	if err != nil {
		return nil, err
	}

	return &models.OutboundPolicyGORM{
		ID:                      policy.ID,
		TenantID:                policy.TenantID,
		Name:                    policy.Name,
		Target:                  string(policy.Target),
		Enabled:                 policy.Enabled,
		AllowedSchemesJSON:      string(schemesJSON),
		AllowedHostPatternsJSON: string(hostsJSON),
		AllowedPathPatternsJSON: string(pathsJSON),
		AllowedPortsJSON:        string(portsJSON),
		BlockPrivateIPs:         policy.BlockPrivateIPs,
		BlockLoopbackIPs:        policy.BlockLoopbackIPs,
		BlockLinkLocalIPs:       policy.BlockLinkLocalIPs,
		BlockMulticastIPs:       policy.BlockMulticastIPs,
		BlockLocalhostNames:     policy.BlockLocalhostNames,
		DisableRedirects:        policy.DisableRedirects,
		RequireDNSResolve:       policy.RequireDNSResolve,
		RequestTimeoutSeconds:   int64(policy.RequestTimeoutSeconds),
		MaxResponseBytes:        policy.MaxResponseBytes,
		CreatedAt:               policy.CreatedAt,
		UpdatedAt:               policy.UpdatedAt,
	}, nil
}
