package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
	"gorm.io/gorm"
)

type TenantGORM struct {
	ID          string         `gorm:"primaryKey;type:varchar(255)"`
	Name        string         `gorm:"type:varchar(255);not null;uniqueIndex"`
	DisplayName string         `gorm:"type:varchar(255)"`
	Description string         `gorm:"type:text"`
	CreatedAt   time.Time      `gorm:"autoCreateTime"`
	UpdatedAt   time.Time      `gorm:"autoUpdateTime"`
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

func (TenantGORM) TableName() string { return "tenants" }

func (t *TenantGORM) BeforeCreate(tx *gorm.DB) (err error) {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	return
}

func (m *TenantGORM) ToDomain() *entity.Tenant {
	return &entity.Tenant{
		ID:          m.ID,
		Name:        m.Name,
		DisplayName: m.DisplayName,
		Description: m.Description,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}
}

func FromDomainTenant(e *entity.Tenant) *TenantGORM {
	return &TenantGORM{
		ID:          e.ID,
		Name:        e.Name,
		DisplayName: e.DisplayName,
		Description: e.Description,
	}
}
