package repository

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"gorm.io/gorm"
)

type auditLogRepository struct {
	db *gorm.DB
}

func NewAuditLogRepository(db *gorm.DB) port.AuditLogRepository {
	return &auditLogRepository{db: db}
}

func (r *auditLogRepository) Save(ctx context.Context, log *model.AuditLog) error {
	dbModel := models.FromDomainAuditLog(log)
	return r.db.WithContext(ctx).Create(dbModel).Error
}

func (r *auditLogRepository) ListByTenant(ctx context.Context, tenantID string, limit, offset int) ([]*model.AuditLog, error) {
	var dbModels []models.AuditLogGORM
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("created_at desc").
		Limit(limit).
		Offset(offset).
		Find(&dbModels).Error; err != nil {
		return nil, err
	}

	var entities []*model.AuditLog
	for _, m := range dbModels {
		entities = append(entities, m.ToDomain())
	}
	return entities, nil
}

func (r *auditLogRepository) GetAuthActivityCounts(ctx context.Context, since time.Time) (map[string]map[string]int64, int64, int64, error) {
	var dbModels []models.AuditLogGORM
	actions := []string{
		"auth.login.accept",
		"provider.login.success",
		"auth.login.reject",
		"auth.ldap.bind.fail",
		"auth.ldap.connection.fail",
	}

	if err := r.db.WithContext(ctx).
		Where("created_at >= ? AND action IN ?", since, actions).
		Find(&dbModels).Error; err != nil {
		return nil, 0, 0, err
	}

	counts := map[string]map[string]int64{
		"oidc": {"success": 0, "failure": 0},
		"saml": {"success": 0, "failure": 0},
		"ldap": {"success": 0, "failure": 0},
	}
	var totalSuccess, totalFailure int64

	for _, m := range dbModels {
		var details map[string]interface{}
		if len(m.Details) > 0 {
			_ = json.Unmarshal(m.Details, &details)
		}

		protocol, _ := details["protocol"].(string)
		providerType, _ := details["provider_type"].(string)

		switch m.Action {
		case "auth.login.accept", "provider.login.success":
			totalSuccess++
			if protocol != "" {
				counts[protocol]["success"]++
			}
			if providerType == "ldap" {
				counts["ldap"]["success"]++
			}
		case "auth.login.reject":
			totalFailure++
			if protocol != "" {
				counts[protocol]["failure"]++
			}
		case "auth.ldap.bind.fail", "auth.ldap.connection.fail":
			totalFailure++
			counts["ldap"]["failure"]++
		}
	}

	return counts, totalSuccess, totalFailure, nil
}

func (r *auditLogRepository) GetAuthFailureMetrics(ctx context.Context, since time.Time) (*model.AuthFailures, error) {
	var dbModels []models.AuditLogGORM
	actions := []string{
		"auth.login.reject",
		"auth.ldap.bind.fail",
		"auth.ldap.connection.fail",
	}

	if err := r.db.WithContext(ctx).
		Where("created_at >= ? AND action IN ?", since, actions).
		Find(&dbModels).Error; err != nil {
		return nil, err
	}

	metrics := &model.AuthFailures{
		GeneratedAt: time.Now(),
		Protocols: map[string]model.AuthProtocolFailures{
			"oidc": {Failure: 0, TopReason: ""},
			"saml": {Failure: 0, TopReason: ""},
			"ldap": {Failure: 0, TopReason: ""},
		},
		Reasons: make([]model.AuthFailureReason, 0),
	}

	reasonCounts := make(map[string]int64)
	protoReasonCounts := make(map[string]map[string]int64)
	for p := range metrics.Protocols {
		protoReasonCounts[p] = make(map[string]int64)
	}

	for _, m := range dbModels {
		var details map[string]interface{}
		if len(m.Details) > 0 {
			_ = json.Unmarshal(m.Details, &details)
		}

		protocol, _ := details["protocol"].(string)
		providerType, _ := details["provider_type"].(string)

		// Determine normalized reason
		reason := "unknown"
		if m.Action == "auth.ldap.bind.fail" {
			r, _ := details["reason"].(string)
			if r == "invalid credentials" || r == "user not found" {
				reason = "invalid_credentials"
			}
		} else if m.Action == "auth.ldap.connection.fail" {
			reason = "provider_error"
		} else if m.Action == "auth.login.reject" {
			errName, _ := details["error_name"].(string)
			switch errName {
			case "invalid_request":
				reason = "invalid_request"
			case "invalid_client":
				reason = "invalid_request"
			case "unauthorized_client":
				reason = "invalid_request"
			case "access_denied":
				reason = "invalid_request"
			case "login_request_not_found":
				reason = "expired_challenge"
			case "server_error":
				reason = "internal_error"
			default:
				reason = "unknown"
			}
		}

		metrics.Totals.Failure++
		reasonCounts[reason]++

		if protocol != "" {
			p := metrics.Protocols[protocol]
			p.Failure++
			metrics.Protocols[protocol] = p
			protoReasonCounts[protocol][reason]++
		}
		if providerType == "ldap" {
			p := metrics.Protocols["ldap"]
			p.Failure++
			metrics.Protocols["ldap"] = p
			protoReasonCounts["ldap"][reason]++
		}
	}

	// Finalize reasons list
	for k, v := range reasonCounts {
		metrics.Reasons = append(metrics.Reasons, model.AuthFailureReason{
			Key:   k,
			Count: v,
		})
	}

	// Determine top reasons per protocol
	for proto := range metrics.Protocols {
		rCounts := protoReasonCounts[proto]
		var topReason string = "none"
		var maxCount int64
		for reason, count := range rCounts {
			if count > maxCount {
				maxCount = count
				topReason = reason
			}
		}
		p := metrics.Protocols[proto]
		p.TopReason = topReason
		metrics.Protocols[proto] = p
	}

	return metrics, nil
}

func (r *auditLogRepository) GetRoutingInsights(ctx context.Context, since time.Time) (*model.RoutingInsights, error) {
	var dbModels []models.AuditLogGORM

	if err := r.db.WithContext(ctx).
		Where("created_at >= ? AND action = ?", since, "provider.login.success").
		Find(&dbModels).Error; err != nil {
		return nil, err
	}

	insights := &model.RoutingInsights{
		GeneratedAt: time.Now(),
		Transitions: make([]model.ProtocolTransition, 0),
		Totals:      model.RoutingTotals{},
	}

	transitionCounts := make(map[string]int64)

	for _, m := range dbModels {
		var details map[string]interface{}
		if len(m.Details) > 0 {
			_ = json.Unmarshal(m.Details, &details)
		}

		from, _ := details["protocol"].(string)
		to, _ := details["provider_type"].(string)

		if from == "" || to == "" {
			continue
		}

		key := from + "->" + to
		transitionCounts[key]++

		if from == to {
			insights.Totals.SameProtocol++
		} else {
			insights.Totals.Routed++
		}
	}

	for key, count := range transitionCounts {
		parts := strings.Split(key, "->")
		insights.Transitions = append(insights.Transitions, model.ProtocolTransition{
			From:  parts[0],
			To:    parts[1],
			Count: count,
		})
	}

	return insights, nil
}
