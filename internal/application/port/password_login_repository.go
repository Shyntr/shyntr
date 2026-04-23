package port

import (
	"context"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

// PasswordLoginRepository handles persistence for password login endpoint definitions
// and their tenant assignments.
type PasswordLoginRepository interface {
	// Endpoint CRUD
	CreateEndpoint(ctx context.Context, e *model.PasswordLoginEndpoint) error
	GetEndpointByID(ctx context.Context, id string) (*model.PasswordLoginEndpoint, error)
	UpdateEndpoint(ctx context.Context, e *model.PasswordLoginEndpoint) error
	DeleteEndpoint(ctx context.Context, id string) error
	ListEndpoints(ctx context.Context) ([]*model.PasswordLoginEndpoint, error)

	// Assignment CRUD
	CreateAssignment(ctx context.Context, a *model.PasswordLoginAssignment) error
	GetAssignmentByID(ctx context.Context, id string) (*model.PasswordLoginAssignment, error)
	UpdateAssignment(ctx context.Context, a *model.PasswordLoginAssignment) error
	DeleteAssignment(ctx context.Context, id string) error
	// ListAssignments lists assignments. When tenantID is non-nil, filters by that tenant.
	// When tenantID is nil, returns all assignments (global + tenant-specific).
	ListAssignments(ctx context.Context, tenantID *string) ([]*model.PasswordLoginAssignment, error)

	// CountActiveAssignmentsForScope counts enabled assignments whose endpoint is also active,
	// scoped to a specific tenant (non-nil tenantID) or the global pool (nil tenantID).
	// Used to enforce the single-active-assignment rule before creating a new assignment.
	CountActiveAssignmentsForScope(ctx context.Context, tenantID *string) (int64, error)

	// ResolveForTenant returns the active PasswordLoginEndpoint for the given tenant.
	// Precedence: tenant-specific enabled assignment → global enabled assignment → nil.
	// Returns an error if multiple active assignments exist at the same precedence level.
	ResolveForTenant(ctx context.Context, tenantID string) (*model.PasswordLoginEndpoint, error)
}
