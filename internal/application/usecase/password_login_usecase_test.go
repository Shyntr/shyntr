package usecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Full-featured stub for PasswordLoginRepository used in use-case tests.
// ---------------------------------------------------------------------------

type fakePasswordLoginRepo struct {
	endpoints   map[string]*model.PasswordLoginEndpoint
	assignments map[string]*model.PasswordLoginAssignment
	// For scope-count simulation:
	// key = "<tenantID>" or "<global>" → count of active assignments
	activeScopeCounts map[string]int64
	resolved          *model.PasswordLoginEndpoint
	resolveErr        error
}

func newFakePwdRepo() *fakePasswordLoginRepo {
	return &fakePasswordLoginRepo{
		endpoints:         make(map[string]*model.PasswordLoginEndpoint),
		assignments:       make(map[string]*model.PasswordLoginAssignment),
		activeScopeCounts: make(map[string]int64),
	}
}

func scopeKey(tenantID *string) string {
	if tenantID == nil {
		return "<global>"
	}
	return *tenantID
}

func (r *fakePasswordLoginRepo) CreateEndpoint(_ context.Context, e *model.PasswordLoginEndpoint) error {
	if _, ok := r.endpoints[e.ID]; ok {
		return errors.New("duplicate endpoint id")
	}
	cp := *e
	cp.CreatedAt = time.Now()
	cp.UpdatedAt = time.Now()
	r.endpoints[e.ID] = &cp
	return nil
}

func (r *fakePasswordLoginRepo) GetEndpointByID(_ context.Context, id string) (*model.PasswordLoginEndpoint, error) {
	e, ok := r.endpoints[id]
	if !ok {
		return nil, errors.New("password login endpoint not found")
	}
	return e, nil
}

func (r *fakePasswordLoginRepo) UpdateEndpoint(_ context.Context, e *model.PasswordLoginEndpoint) error {
	if _, ok := r.endpoints[e.ID]; !ok {
		return errors.New("password login endpoint not found")
	}
	cp := *e
	cp.UpdatedAt = time.Now()
	r.endpoints[e.ID] = &cp
	return nil
}

func (r *fakePasswordLoginRepo) DeleteEndpoint(_ context.Context, id string) error {
	if _, ok := r.endpoints[id]; !ok {
		return errors.New("password login endpoint not found")
	}
	delete(r.endpoints, id)
	return nil
}

func (r *fakePasswordLoginRepo) ListEndpoints(_ context.Context) ([]*model.PasswordLoginEndpoint, error) {
	out := make([]*model.PasswordLoginEndpoint, 0, len(r.endpoints))
	for _, e := range r.endpoints {
		cp := *e
		out = append(out, &cp)
	}
	return out, nil
}

func (r *fakePasswordLoginRepo) CreateAssignment(_ context.Context, a *model.PasswordLoginAssignment) error {
	if _, ok := r.assignments[a.ID]; ok {
		return errors.New("duplicate assignment id")
	}
	cp := *a
	cp.CreatedAt = time.Now()
	cp.UpdatedAt = time.Now()
	r.assignments[a.ID] = &cp
	return nil
}

func (r *fakePasswordLoginRepo) GetAssignmentByID(_ context.Context, id string) (*model.PasswordLoginAssignment, error) {
	a, ok := r.assignments[id]
	if !ok {
		return nil, errors.New("password login assignment not found")
	}
	return a, nil
}

func (r *fakePasswordLoginRepo) UpdateAssignment(_ context.Context, a *model.PasswordLoginAssignment) error {
	if _, ok := r.assignments[a.ID]; !ok {
		return errors.New("password login assignment not found")
	}
	cp := *a
	cp.UpdatedAt = time.Now()
	r.assignments[a.ID] = &cp
	return nil
}

func (r *fakePasswordLoginRepo) DeleteAssignment(_ context.Context, id string) error {
	if _, ok := r.assignments[id]; !ok {
		return errors.New("password login assignment not found")
	}
	delete(r.assignments, id)
	return nil
}

func (r *fakePasswordLoginRepo) ListAssignments(_ context.Context, tenantID *string) ([]*model.PasswordLoginAssignment, error) {
	out := make([]*model.PasswordLoginAssignment, 0)
	for _, a := range r.assignments {
		if tenantID == nil {
			out = append(out, a)
			continue
		}
		if a.TenantID != nil && *a.TenantID == *tenantID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (r *fakePasswordLoginRepo) CountActiveAssignmentsForScope(_ context.Context, tenantID *string) (int64, error) {
	return r.activeScopeCounts[scopeKey(tenantID)], nil
}

func (r *fakePasswordLoginRepo) ResolveForTenant(_ context.Context, _ string) (*model.PasswordLoginEndpoint, error) {
	return r.resolved, r.resolveErr
}

// ---------------------------------------------------------------------------
// Endpoint validation tests
// ---------------------------------------------------------------------------

func TestCreateEndpoint_ValidHTTPS(t *testing.T) {
	repo := newFakePwdRepo()
	uc := usecase.NewPasswordLoginUseCase(repo)

	ep, err := uc.CreateEndpoint(context.Background(), &model.PasswordLoginEndpoint{
		ID:       "ep-1",
		Name:     "Test Verifier",
		LoginURL: "https://verifier.example.com/auth/password",
		IsActive: true,
	})

	require.NoError(t, err)
	assert.Equal(t, "https://verifier.example.com/auth/password", ep.LoginURL)
	assert.Equal(t, "Test Verifier", ep.Name)
}

func TestCreateEndpoint_ValidHTTP(t *testing.T) {
	repo := newFakePwdRepo()
	uc := usecase.NewPasswordLoginUseCase(repo)

	ep, err := uc.CreateEndpoint(context.Background(), &model.PasswordLoginEndpoint{
		ID:       "ep-http",
		Name:     "Dev Verifier",
		LoginURL: "http://localhost:9000/verify",
		IsActive: true,
	})

	require.NoError(t, err)
	assert.Equal(t, "http://localhost:9000/verify", ep.LoginURL)
}

func TestCreateEndpoint_EmptyLoginURLRejected(t *testing.T) {
	repo := newFakePwdRepo()
	uc := usecase.NewPasswordLoginUseCase(repo)

	_, err := uc.CreateEndpoint(context.Background(), &model.PasswordLoginEndpoint{
		ID:       "ep-bad",
		Name:     "Bad",
		LoginURL: "",
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, usecase.ErrInvalidPasswordLoginURL)
}

func TestCreateEndpoint_NonHTTPSchemeRejected(t *testing.T) {
	repo := newFakePwdRepo()
	uc := usecase.NewPasswordLoginUseCase(repo)

	for _, badURL := range []string{
		"ftp://example.com/verify",
		"file:///etc/passwd",
		"ldap://example.com/verify",
		"javascript:alert(1)",
		"//example.com/verify", // scheme-relative
	} {
		_, err := uc.CreateEndpoint(context.Background(), &model.PasswordLoginEndpoint{
			ID:       "ep-bad",
			Name:     "Bad",
			LoginURL: badURL,
		})
		require.Errorf(t, err, "expected rejection for URL: %s", badURL)
		assert.ErrorIs(t, err, usecase.ErrInvalidPasswordLoginURL, "URL %s", badURL)
	}
}

func TestCreateEndpoint_EmptyNameRejected(t *testing.T) {
	repo := newFakePwdRepo()
	uc := usecase.NewPasswordLoginUseCase(repo)

	_, err := uc.CreateEndpoint(context.Background(), &model.PasswordLoginEndpoint{
		ID:       "ep-noname",
		Name:     "   ",
		LoginURL: "https://verifier.example.com/verify",
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, usecase.ErrEmptyPasswordLoginName)
}

func TestCreateEndpoint_TrimsWhitespace(t *testing.T) {
	repo := newFakePwdRepo()
	uc := usecase.NewPasswordLoginUseCase(repo)

	ep, err := uc.CreateEndpoint(context.Background(), &model.PasswordLoginEndpoint{
		ID:       "ep-trim",
		Name:     "  My Verifier  ",
		LoginURL: "  https://verifier.example.com/verify  ",
		IsActive: true,
	})

	require.NoError(t, err)
	assert.Equal(t, "My Verifier", ep.Name)
	assert.Equal(t, "https://verifier.example.com/verify", ep.LoginURL)
}

func TestUpdateEndpoint_InvalidURLRejected(t *testing.T) {
	repo := newFakePwdRepo()
	uc := usecase.NewPasswordLoginUseCase(repo)

	_, err := uc.CreateEndpoint(context.Background(), &model.PasswordLoginEndpoint{
		ID:       "ep-upd",
		Name:     "Verifier",
		LoginURL: "https://verifier.example.com/verify",
		IsActive: true,
	})
	require.NoError(t, err)

	_, err = uc.UpdateEndpoint(context.Background(), &model.PasswordLoginEndpoint{
		ID:       "ep-upd",
		Name:     "Verifier",
		LoginURL: "not-a-url",
		IsActive: true,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, usecase.ErrInvalidPasswordLoginURL)
}

// ---------------------------------------------------------------------------
// Assignment tests
// ---------------------------------------------------------------------------

func tenantStr(s string) *string { return &s }

func TestCreateAssignment_RejectsWhenEndpointNotFound(t *testing.T) {
	repo := newFakePwdRepo()
	uc := usecase.NewPasswordLoginUseCase(repo)

	_, err := uc.CreateAssignment(context.Background(), &model.PasswordLoginAssignment{
		ID:                      "asgn-1",
		TenantID:                tenantStr("tenant-a"),
		PasswordLoginEndpointID: "nonexistent-endpoint",
		Enabled:                 true,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, usecase.ErrPasswordLoginEndpointNotFound)
}

func TestCreateAssignment_RejectsDuplicateActiveAssignment(t *testing.T) {
	repo := newFakePwdRepo()
	// Pre-set count to 1 for this tenant scope to simulate existing active assignment.
	tid := tenantStr("tenant-a")
	repo.activeScopeCounts[scopeKey(tid)] = 1

	// Also put an endpoint so the first check passes
	repo.endpoints["ep-1"] = &model.PasswordLoginEndpoint{
		ID:       "ep-1",
		Name:     "Verifier",
		LoginURL: "https://v.example.com/verify",
		IsActive: true,
	}

	uc := usecase.NewPasswordLoginUseCase(repo)

	_, err := uc.CreateAssignment(context.Background(), &model.PasswordLoginAssignment{
		ID:                      "asgn-dup",
		TenantID:                tid,
		PasswordLoginEndpointID: "ep-1",
		Enabled:                 true,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, usecase.ErrDuplicateActivePasswordAssignment)
}

func TestCreateAssignment_DisabledAssignmentSkipsDuplicateCheck(t *testing.T) {
	repo := newFakePwdRepo()
	// Even with an existing active, a disabled assignment is allowed.
	tid := tenantStr("tenant-a")
	repo.activeScopeCounts[scopeKey(tid)] = 1
	repo.endpoints["ep-1"] = &model.PasswordLoginEndpoint{
		ID:       "ep-1",
		Name:     "Verifier",
		LoginURL: "https://v.example.com/verify",
		IsActive: true,
	}

	uc := usecase.NewPasswordLoginUseCase(repo)

	created, err := uc.CreateAssignment(context.Background(), &model.PasswordLoginAssignment{
		ID:                      "asgn-disabled",
		TenantID:                tid,
		PasswordLoginEndpointID: "ep-1",
		Enabled:                 false, // disabled → no conflict check
	})

	require.NoError(t, err)
	assert.False(t, created.Enabled)
}

func TestCreateAssignment_GlobalAssignmentAllowed(t *testing.T) {
	repo := newFakePwdRepo()
	repo.endpoints["ep-global"] = &model.PasswordLoginEndpoint{
		ID:       "ep-global",
		Name:     "Global Verifier",
		LoginURL: "https://global.example.com/verify",
		IsActive: true,
	}

	uc := usecase.NewPasswordLoginUseCase(repo)

	created, err := uc.CreateAssignment(context.Background(), &model.PasswordLoginAssignment{
		ID:                      "asgn-global",
		TenantID:                nil, // global
		PasswordLoginEndpointID: "ep-global",
		Enabled:                 true,
	})

	require.NoError(t, err)
	assert.Nil(t, created.TenantID, "global assignment must have nil tenant_id")
}
