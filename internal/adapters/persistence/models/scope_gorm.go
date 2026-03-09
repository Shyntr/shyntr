package models

import (
	"time"

	"github.com/lib/pq"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
)

type ScopeGORM struct {
	ID          string         `gorm:"primaryKey;type:varchar(255)"`
	TenantID    string         `gorm:"type:varchar(255);not null;uniqueIndex:idx_tenant_scope_name"`
	Name        string         `gorm:"type:varchar(255);not null;uniqueIndex:idx_tenant_scope_name"`
	Description string         `gorm:"type:text"`
	Claims      pq.StringArray `gorm:"type:text[]"`
	IsSystem    bool           `gorm:"default:false"`
	Active      bool           `gorm:"default:true;index"`
	CreatedAt   time.Time      `gorm:"autoCreateTime"`
	UpdatedAt   time.Time      `gorm:"autoUpdateTime"`
}

func (ScopeGORM) TableName() string {
	return "scopes"
}

func (m *ScopeGORM) ToDomain() *entity.Scope {
	return &entity.Scope{
		ID:          m.ID,
		TenantID:    m.TenantID,
		Name:        m.Name,
		Description: m.Description,
		Claims:      m.Claims,
		IsSystem:    m.IsSystem,
		Active:      m.Active,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}
}

func FromDomainScope(e *entity.Scope) *ScopeGORM {
	return &ScopeGORM{
		ID:          e.ID,
		TenantID:    e.TenantID,
		Name:        e.Name,
		Description: e.Description,
		Claims:      e.Claims,
		IsSystem:    e.IsSystem,
		Active:      e.Active,
	}
}
