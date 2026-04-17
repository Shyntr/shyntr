package repository

import (
	"context"
	"encoding/json"
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
