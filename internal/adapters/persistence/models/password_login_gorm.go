package models

import (
	"time"

	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PasswordLoginEndpointGORM persists password verifier endpoint definitions.
// Table: password_login_endpoints
type PasswordLoginEndpointGORM struct {
	ID        string         `gorm:"primaryKey;type:varchar(255)"`
	Name      string         `gorm:"type:varchar(255);not null"`
	LoginURL  string         `gorm:"type:varchar(2048);not null"`
	IsActive  bool           `gorm:"not null"`
	CreatedAt time.Time      `gorm:"autoCreateTime"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (PasswordLoginEndpointGORM) TableName() string { return "password_login_endpoints" }

func (e *PasswordLoginEndpointGORM) BeforeCreate(_ *gorm.DB) error {
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	return nil
}

func (e *PasswordLoginEndpointGORM) ToDomain() *model.PasswordLoginEndpoint {
	return &model.PasswordLoginEndpoint{
		ID:        e.ID,
		Name:      e.Name,
		LoginURL:  e.LoginURL,
		IsActive:  e.IsActive,
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
	}
}

func FromDomainPasswordLoginEndpoint(e *model.PasswordLoginEndpoint) *PasswordLoginEndpointGORM {
	return &PasswordLoginEndpointGORM{
		ID:       e.ID,
		Name:     e.Name,
		LoginURL: e.LoginURL,
		IsActive: e.IsActive,
	}
}

// PasswordLoginAssignmentGORM assigns an endpoint to a tenant (or globally when TenantID is NULL).
// Table: password_login_assignments
type PasswordLoginAssignmentGORM struct {
	ID                      string         `gorm:"primaryKey;type:varchar(255)"`
	TenantID                *string        `gorm:"type:varchar(255);index"`
	PasswordLoginEndpointID string         `gorm:"type:varchar(255);not null;index"`
	Enabled                 bool           `gorm:"not null"`
	CreatedAt               time.Time      `gorm:"autoCreateTime"`
	UpdatedAt               time.Time      `gorm:"autoUpdateTime"`
	DeletedAt               gorm.DeletedAt `gorm:"index"`
}

func (PasswordLoginAssignmentGORM) TableName() string { return "password_login_assignments" }

func (a *PasswordLoginAssignmentGORM) BeforeCreate(_ *gorm.DB) error {
	if a.ID == "" {
		a.ID = uuid.New().String()
	}
	return nil
}

func (a *PasswordLoginAssignmentGORM) ToDomain() *model.PasswordLoginAssignment {
	return &model.PasswordLoginAssignment{
		ID:                      a.ID,
		TenantID:                a.TenantID,
		PasswordLoginEndpointID: a.PasswordLoginEndpointID,
		Enabled:                 a.Enabled,
		CreatedAt:               a.CreatedAt,
		UpdatedAt:               a.UpdatedAt,
	}
}

func FromDomainPasswordLoginAssignment(a *model.PasswordLoginAssignment) *PasswordLoginAssignmentGORM {
	return &PasswordLoginAssignmentGORM{
		ID:                      a.ID,
		TenantID:                a.TenantID,
		PasswordLoginEndpointID: a.PasswordLoginEndpointID,
		Enabled:                 a.Enabled,
	}
}
