package repository

import (
	"context"
	"errors"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"gorm.io/gorm"
)

type passwordLoginRepository struct {
	db *gorm.DB
}

func NewPasswordLoginRepository(db *gorm.DB) port.PasswordLoginRepository {
	return &passwordLoginRepository{db: db}
}

// ----- Endpoints -----

func (r *passwordLoginRepository) CreateEndpoint(ctx context.Context, e *model.PasswordLoginEndpoint) error {
	return r.db.WithContext(ctx).Create(models.FromDomainPasswordLoginEndpoint(e)).Error
}

func (r *passwordLoginRepository) GetEndpointByID(ctx context.Context, id string) (*model.PasswordLoginEndpoint, error) {
	var m models.PasswordLoginEndpointGORM
	if err := r.db.WithContext(ctx).First(&m, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("password login endpoint not found")
		}
		return nil, err
	}
	return m.ToDomain(), nil
}

func (r *passwordLoginRepository) UpdateEndpoint(ctx context.Context, e *model.PasswordLoginEndpoint) error {
	result := r.db.WithContext(ctx).
		Model(&models.PasswordLoginEndpointGORM{}).
		Where("id = ?", e.ID).
		Updates(map[string]interface{}{
			"name":      e.Name,
			"login_url": e.LoginURL,
			"is_active": e.IsActive,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("password login endpoint not found")
	}
	return nil
}

func (r *passwordLoginRepository) DeleteEndpoint(ctx context.Context, id string) error {
	result := r.db.WithContext(ctx).Delete(&models.PasswordLoginEndpointGORM{}, "id = ?", id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("password login endpoint not found")
	}
	return nil
}

func (r *passwordLoginRepository) ListEndpoints(ctx context.Context) ([]*model.PasswordLoginEndpoint, error) {
	var dbModels []models.PasswordLoginEndpointGORM
	if err := r.db.WithContext(ctx).Find(&dbModels).Error; err != nil {
		return nil, err
	}
	result := make([]*model.PasswordLoginEndpoint, 0, len(dbModels))
	for i := range dbModels {
		result = append(result, dbModels[i].ToDomain())
	}
	return result, nil
}

// ----- Assignments -----

func (r *passwordLoginRepository) CreateAssignment(ctx context.Context, a *model.PasswordLoginAssignment) error {
	return r.db.WithContext(ctx).Create(models.FromDomainPasswordLoginAssignment(a)).Error
}

func (r *passwordLoginRepository) GetAssignmentByID(ctx context.Context, id string) (*model.PasswordLoginAssignment, error) {
	var m models.PasswordLoginAssignmentGORM
	if err := r.db.WithContext(ctx).First(&m, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("password login assignment not found")
		}
		return nil, err
	}
	return m.ToDomain(), nil
}

func (r *passwordLoginRepository) UpdateAssignment(ctx context.Context, a *model.PasswordLoginAssignment) error {
	result := r.db.WithContext(ctx).
		Model(&models.PasswordLoginAssignmentGORM{}).
		Where("id = ?", a.ID).
		Updates(map[string]interface{}{
			"password_login_endpoint_id": a.PasswordLoginEndpointID,
			"enabled":                    a.Enabled,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("password login assignment not found")
	}
	return nil
}

func (r *passwordLoginRepository) DeleteAssignment(ctx context.Context, id string) error {
	result := r.db.WithContext(ctx).Delete(&models.PasswordLoginAssignmentGORM{}, "id = ?", id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("password login assignment not found")
	}
	return nil
}

func (r *passwordLoginRepository) ListAssignments(ctx context.Context, tenantID *string) ([]*model.PasswordLoginAssignment, error) {
	var dbModels []models.PasswordLoginAssignmentGORM
	query := r.db.WithContext(ctx)
	if tenantID != nil {
		query = query.Where("tenant_id = ?", *tenantID)
	}
	if err := query.Find(&dbModels).Error; err != nil {
		return nil, err
	}
	result := make([]*model.PasswordLoginAssignment, 0, len(dbModels))
	for i := range dbModels {
		result = append(result, dbModels[i].ToDomain())
	}
	return result, nil
}

func (r *passwordLoginRepository) CountActiveAssignmentsForScope(ctx context.Context, tenantID *string) (int64, error) {
	var count int64
	query := r.db.WithContext(ctx).
		Table("password_login_assignments").
		Joins(`INNER JOIN password_login_endpoints
			ON password_login_endpoints.id = password_login_assignments.password_login_endpoint_id
			AND password_login_endpoints.deleted_at IS NULL`).
		Where(
			"password_login_assignments.enabled = ? AND password_login_endpoints.is_active = ? AND password_login_assignments.deleted_at IS NULL",
			true, true,
		)

	if tenantID == nil {
		query = query.Where("password_login_assignments.tenant_id IS NULL")
	} else {
		query = query.Where("password_login_assignments.tenant_id = ?", *tenantID)
	}

	return count, query.Count(&count).Error
}

// ResolveForTenant resolves the active password login endpoint for tenantID.
// Precedence: tenant-specific enabled assignment first, then global enabled assignment.
// Returns nil if no active assignment exists.
// Returns an error if multiple active assignments exist at the same level (ambiguous config).
func (r *passwordLoginRepository) ResolveForTenant(ctx context.Context, tenantID string) (*model.PasswordLoginEndpoint, error) {
	// 1. Tenant-specific assignment
	endpoint, err := r.resolveByScope(ctx, &tenantID)
	if err != nil {
		return nil, err
	}
	if endpoint != nil {
		return endpoint, nil
	}

	// 2. Global assignment
	return r.resolveByScope(ctx, nil)
}

// resolveByScope resolves a single active endpoint for the given scope.
// tenantID == nil means the global scope (tenant_id IS NULL in the DB).
func (r *passwordLoginRepository) resolveByScope(ctx context.Context, tenantID *string) (*model.PasswordLoginEndpoint, error) {
	var endpoints []models.PasswordLoginEndpointGORM

	query := r.db.WithContext(ctx).
		Table("password_login_endpoints").
		Joins(`INNER JOIN password_login_assignments
			ON password_login_assignments.password_login_endpoint_id = password_login_endpoints.id
			AND password_login_assignments.deleted_at IS NULL`).
		Where(
			"password_login_endpoints.is_active = ? AND password_login_endpoints.deleted_at IS NULL AND password_login_assignments.enabled = ?",
			true, true,
		)

	if tenantID == nil {
		query = query.Where("password_login_assignments.tenant_id IS NULL")
	} else {
		query = query.Where("password_login_assignments.tenant_id = ?", *tenantID)
	}

	if err := query.Find(&endpoints).Error; err != nil {
		return nil, err
	}

	switch len(endpoints) {
	case 0:
		return nil, nil
	case 1:
		return endpoints[0].ToDomain(), nil
	default:
		return nil, errors.New("ambiguous password login configuration: multiple active assignments found for this tenant")
	}
}
