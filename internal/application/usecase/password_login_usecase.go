package usecase

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/google/uuid"
)

var (
	ErrInvalidPasswordLoginURL           = errors.New("login_url must be an absolute http or https URL with a non-empty host")
	ErrEmptyPasswordLoginName            = errors.New("name must not be empty")
	ErrPasswordLoginEndpointNotFound     = errors.New("password login endpoint not found")
	ErrPasswordLoginAssignmentNotFound   = errors.New("password login assignment not found")
	ErrDuplicateActivePasswordAssignment = errors.New("an active password login assignment already exists for this scope; disable or delete it first")
)

// PasswordLoginUseCase provides admin operations for password login endpoint
// definitions and their tenant assignments.
type PasswordLoginUseCase interface {
	// Endpoint operations
	CreateEndpoint(ctx context.Context, e *model.PasswordLoginEndpoint) (*model.PasswordLoginEndpoint, error)
	GetEndpoint(ctx context.Context, id string) (*model.PasswordLoginEndpoint, error)
	UpdateEndpoint(ctx context.Context, e *model.PasswordLoginEndpoint) (*model.PasswordLoginEndpoint, error)
	DeleteEndpoint(ctx context.Context, id string) error
	ListEndpoints(ctx context.Context) ([]*model.PasswordLoginEndpoint, error)

	// Assignment operations
	CreateAssignment(ctx context.Context, a *model.PasswordLoginAssignment) (*model.PasswordLoginAssignment, error)
	GetAssignment(ctx context.Context, id string) (*model.PasswordLoginAssignment, error)
	UpdateAssignment(ctx context.Context, a *model.PasswordLoginAssignment) (*model.PasswordLoginAssignment, error)
	DeleteAssignment(ctx context.Context, id string) error
	ListAssignments(ctx context.Context, tenantID *string) ([]*model.PasswordLoginAssignment, error)
}

type passwordLoginUseCase struct {
	repo port.PasswordLoginRepository
}

func NewPasswordLoginUseCase(repo port.PasswordLoginRepository) PasswordLoginUseCase {
	return &passwordLoginUseCase{repo: repo}
}

// validateAndNormalizeURL validates that rawURL is an absolute http or https URL
// and returns the trimmed form. Empty string and non-http(s) schemes are rejected.
func validateAndNormalizeURL(rawURL string) (string, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "", ErrInvalidPasswordLoginURL
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", ErrInvalidPasswordLoginURL
	}
	return trimmed, nil
}

// ----- Endpoint operations -----

func (uc *passwordLoginUseCase) CreateEndpoint(ctx context.Context, e *model.PasswordLoginEndpoint) (*model.PasswordLoginEndpoint, error) {
	cleaned, err := validateAndNormalizeURL(e.LoginURL)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(e.Name)
	if name == "" {
		return nil, ErrEmptyPasswordLoginName
	}

	e.LoginURL = cleaned
	e.Name = name
	if e.ID == "" {
		e.ID = uuid.New().String()
	}

	if err := uc.repo.CreateEndpoint(ctx, e); err != nil {
		return nil, err
	}
	return uc.repo.GetEndpointByID(ctx, e.ID)
}

func (uc *passwordLoginUseCase) GetEndpoint(ctx context.Context, id string) (*model.PasswordLoginEndpoint, error) {
	return uc.repo.GetEndpointByID(ctx, id)
}

func (uc *passwordLoginUseCase) UpdateEndpoint(ctx context.Context, e *model.PasswordLoginEndpoint) (*model.PasswordLoginEndpoint, error) {
	cleaned, err := validateAndNormalizeURL(e.LoginURL)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(e.Name)
	if name == "" {
		return nil, ErrEmptyPasswordLoginName
	}

	e.LoginURL = cleaned
	e.Name = name

	if err := uc.repo.UpdateEndpoint(ctx, e); err != nil {
		return nil, err
	}
	return uc.repo.GetEndpointByID(ctx, e.ID)
}

func (uc *passwordLoginUseCase) DeleteEndpoint(ctx context.Context, id string) error {
	return uc.repo.DeleteEndpoint(ctx, id)
}

func (uc *passwordLoginUseCase) ListEndpoints(ctx context.Context) ([]*model.PasswordLoginEndpoint, error) {
	return uc.repo.ListEndpoints(ctx)
}

// ----- Assignment operations -----

func (uc *passwordLoginUseCase) CreateAssignment(ctx context.Context, a *model.PasswordLoginAssignment) (*model.PasswordLoginAssignment, error) {
	// Validate that the referenced endpoint exists.
	if _, err := uc.repo.GetEndpointByID(ctx, a.PasswordLoginEndpointID); err != nil {
		return nil, ErrPasswordLoginEndpointNotFound
	}

	// Enforce single-active-assignment rule: reject if another active assignment
	// already exists for the same scope (tenant-specific or global).
	if a.Enabled {
		count, err := uc.repo.CountActiveAssignmentsForScope(ctx, a.TenantID)
		if err != nil {
			return nil, err
		}
		if count > 0 {
			return nil, ErrDuplicateActivePasswordAssignment
		}
	}

	if a.ID == "" {
		a.ID = uuid.New().String()
	}

	if err := uc.repo.CreateAssignment(ctx, a); err != nil {
		return nil, err
	}
	return uc.repo.GetAssignmentByID(ctx, a.ID)
}

func (uc *passwordLoginUseCase) GetAssignment(ctx context.Context, id string) (*model.PasswordLoginAssignment, error) {
	return uc.repo.GetAssignmentByID(ctx, id)
}

func (uc *passwordLoginUseCase) UpdateAssignment(ctx context.Context, a *model.PasswordLoginAssignment) (*model.PasswordLoginAssignment, error) {
	// Validate referenced endpoint still exists.
	if _, err := uc.repo.GetEndpointByID(ctx, a.PasswordLoginEndpointID); err != nil {
		return nil, ErrPasswordLoginEndpointNotFound
	}

	if err := uc.repo.UpdateAssignment(ctx, a); err != nil {
		return nil, err
	}
	return uc.repo.GetAssignmentByID(ctx, a.ID)
}

func (uc *passwordLoginUseCase) DeleteAssignment(ctx context.Context, id string) error {
	return uc.repo.DeleteAssignment(ctx, id)
}

func (uc *passwordLoginUseCase) ListAssignments(ctx context.Context, tenantID *string) ([]*model.PasswordLoginAssignment, error) {
	return uc.repo.ListAssignments(ctx, tenantID)
}
