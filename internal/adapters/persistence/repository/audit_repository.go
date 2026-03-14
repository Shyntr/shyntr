package repository

import (
	"context"

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
