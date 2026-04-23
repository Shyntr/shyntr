package repository_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/repository"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupPasswordLoginDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbName := fmt.Sprintf("file:pwd_login_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.PasswordLoginEndpointGORM{},
		&models.PasswordLoginAssignmentGORM{},
	))
	return db
}

func newEndpoint(name, loginURL string) *model.PasswordLoginEndpoint {
	return &model.PasswordLoginEndpoint{
		ID:       uuid.New().String(),
		Name:     name,
		LoginURL: loginURL,
		IsActive: true,
	}
}

func newAssignment(tenantID *string, endpointID string, enabled bool) *model.PasswordLoginAssignment {
	return &model.PasswordLoginAssignment{
		ID:                      uuid.New().String(),
		TenantID:                tenantID,
		PasswordLoginEndpointID: endpointID,
		Enabled:                 enabled,
	}
}

func strPtr(s string) *string { return &s }

// ----- Endpoint CRUD -----

func TestPasswordLoginRepo_EndpointCRUD(t *testing.T) {
	db := setupPasswordLoginDB(t)
	repo := repository.NewPasswordLoginRepository(db)
	ctx := context.Background()

	ep := newEndpoint("Test Verifier", "https://verifier.example.com/verify")
	require.NoError(t, repo.CreateEndpoint(ctx, ep))

	fetched, err := repo.GetEndpointByID(ctx, ep.ID)
	require.NoError(t, err)
	assert.Equal(t, ep.Name, fetched.Name)
	assert.Equal(t, ep.LoginURL, fetched.LoginURL)
	assert.True(t, fetched.IsActive)

	fetched.Name = "Updated Verifier"
	fetched.LoginURL = "https://updated.example.com/verify"
	fetched.IsActive = false
	require.NoError(t, repo.UpdateEndpoint(ctx, fetched))

	updated, err := repo.GetEndpointByID(ctx, ep.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Verifier", updated.Name)
	assert.Equal(t, "https://updated.example.com/verify", updated.LoginURL)
	assert.False(t, updated.IsActive)

	require.NoError(t, repo.DeleteEndpoint(ctx, ep.ID))
	_, err = repo.GetEndpointByID(ctx, ep.ID)
	require.Error(t, err, "must return error after deletion")
}

func TestPasswordLoginRepo_ListEndpoints(t *testing.T) {
	db := setupPasswordLoginDB(t)
	repo := repository.NewPasswordLoginRepository(db)
	ctx := context.Background()

	ep1 := newEndpoint("EP1", "https://ep1.example.com/verify")
	ep2 := newEndpoint("EP2", "https://ep2.example.com/verify")
	require.NoError(t, repo.CreateEndpoint(ctx, ep1))
	require.NoError(t, repo.CreateEndpoint(ctx, ep2))

	list, err := repo.ListEndpoints(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

// ----- Assignment CRUD -----

func TestPasswordLoginRepo_AssignmentCRUD(t *testing.T) {
	db := setupPasswordLoginDB(t)
	repo := repository.NewPasswordLoginRepository(db)
	ctx := context.Background()

	ep := newEndpoint("Verifier", "https://verifier.example.com/verify")
	require.NoError(t, repo.CreateEndpoint(ctx, ep))

	asgn := newAssignment(strPtr("tenant-a"), ep.ID, true)
	require.NoError(t, repo.CreateAssignment(ctx, asgn))

	fetched, err := repo.GetAssignmentByID(ctx, asgn.ID)
	require.NoError(t, err)
	require.NotNil(t, fetched.TenantID)
	assert.Equal(t, "tenant-a", *fetched.TenantID)
	assert.True(t, fetched.Enabled)

	fetched.Enabled = false
	require.NoError(t, repo.UpdateAssignment(ctx, fetched))

	updated, err := repo.GetAssignmentByID(ctx, asgn.ID)
	require.NoError(t, err)
	assert.False(t, updated.Enabled)

	require.NoError(t, repo.DeleteAssignment(ctx, asgn.ID))
	_, err = repo.GetAssignmentByID(ctx, asgn.ID)
	require.Error(t, err, "must return error after deletion")
}

// ----- Resolver tests -----

func TestPasswordLoginRepo_ResolveForTenant_TenantSpecificAssignment(t *testing.T) {
	db := setupPasswordLoginDB(t)
	repo := repository.NewPasswordLoginRepository(db)
	ctx := context.Background()

	ep := newEndpoint("Tenant Verifier", "https://tenant.example.com/verify")
	require.NoError(t, repo.CreateEndpoint(ctx, ep))
	asgn := newAssignment(strPtr("tenant-a"), ep.ID, true)
	require.NoError(t, repo.CreateAssignment(ctx, asgn))

	resolved, err := repo.ResolveForTenant(ctx, "tenant-a")
	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, ep.ID, resolved.ID)
	assert.Equal(t, "https://tenant.example.com/verify", resolved.LoginURL)
}

func TestPasswordLoginRepo_ResolveForTenant_GlobalFallback(t *testing.T) {
	db := setupPasswordLoginDB(t)
	repo := repository.NewPasswordLoginRepository(db)
	ctx := context.Background()

	ep := newEndpoint("Global Verifier", "https://global.example.com/verify")
	require.NoError(t, repo.CreateEndpoint(ctx, ep))
	// Global assignment (tenant_id IS NULL)
	asgn := newAssignment(nil, ep.ID, true)
	require.NoError(t, repo.CreateAssignment(ctx, asgn))

	// tenant-b has no specific assignment → should get global
	resolved, err := repo.ResolveForTenant(ctx, "tenant-b")
	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, ep.ID, resolved.ID)
}

func TestPasswordLoginRepo_ResolveForTenant_TenantSpecificOverridesGlobal(t *testing.T) {
	db := setupPasswordLoginDB(t)
	repo := repository.NewPasswordLoginRepository(db)
	ctx := context.Background()

	globalEP := newEndpoint("Global Verifier", "https://global.example.com/verify")
	require.NoError(t, repo.CreateEndpoint(ctx, globalEP))
	require.NoError(t, repo.CreateAssignment(ctx, newAssignment(nil, globalEP.ID, true)))

	tenantEP := newEndpoint("Tenant Verifier", "https://tenant-specific.example.com/verify")
	require.NoError(t, repo.CreateEndpoint(ctx, tenantEP))
	require.NoError(t, repo.CreateAssignment(ctx, newAssignment(strPtr("tenant-a"), tenantEP.ID, true)))

	resolved, err := repo.ResolveForTenant(ctx, "tenant-a")
	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, tenantEP.ID, resolved.ID, "tenant-specific must override global")
}

func TestPasswordLoginRepo_ResolveForTenant_NoneWhenNoAssignment(t *testing.T) {
	db := setupPasswordLoginDB(t)
	repo := repository.NewPasswordLoginRepository(db)
	ctx := context.Background()

	resolved, err := repo.ResolveForTenant(ctx, "tenant-x")
	require.NoError(t, err)
	assert.Nil(t, resolved, "must return nil when no assignment exists")
}

func TestPasswordLoginRepo_ResolveForTenant_OmitsDisabledAssignment(t *testing.T) {
	db := setupPasswordLoginDB(t)
	repo := repository.NewPasswordLoginRepository(db)
	ctx := context.Background()

	ep := newEndpoint("Verifier", "https://verifier.example.com/verify")
	require.NoError(t, repo.CreateEndpoint(ctx, ep))
	// Assignment is disabled
	asgn := newAssignment(strPtr("tenant-a"), ep.ID, false)
	require.NoError(t, repo.CreateAssignment(ctx, asgn))

	resolved, err := repo.ResolveForTenant(ctx, "tenant-a")
	require.NoError(t, err)
	assert.Nil(t, resolved, "disabled assignment must not be resolved")
}

func TestPasswordLoginRepo_ResolveForTenant_OmitsInactiveEndpoint(t *testing.T) {
	db := setupPasswordLoginDB(t)
	repo := repository.NewPasswordLoginRepository(db)
	ctx := context.Background()

	ep := newEndpoint("Inactive Verifier", "https://verifier.example.com/verify")
	ep.IsActive = false
	require.NoError(t, repo.CreateEndpoint(ctx, ep))
	asgn := newAssignment(strPtr("tenant-a"), ep.ID, true)
	require.NoError(t, repo.CreateAssignment(ctx, asgn))

	resolved, err := repo.ResolveForTenant(ctx, "tenant-a")
	require.NoError(t, err)
	assert.Nil(t, resolved, "inactive endpoint must not be resolved")
}

func TestPasswordLoginRepo_ResolveForTenant_ErrorOnAmbiguousConfig(t *testing.T) {
	db := setupPasswordLoginDB(t)
	repo := repository.NewPasswordLoginRepository(db)
	ctx := context.Background()

	ep1 := newEndpoint("Verifier 1", "https://v1.example.com/verify")
	ep2 := newEndpoint("Verifier 2", "https://v2.example.com/verify")
	require.NoError(t, repo.CreateEndpoint(ctx, ep1))
	require.NoError(t, repo.CreateEndpoint(ctx, ep2))

	require.NoError(t, repo.CreateAssignment(ctx, newAssignment(strPtr("tenant-a"), ep1.ID, true)))
	require.NoError(t, repo.CreateAssignment(ctx, newAssignment(strPtr("tenant-a"), ep2.ID, true)))

	_, err := repo.ResolveForTenant(ctx, "tenant-a")
	require.Error(t, err, "ambiguous config must return error")
	assert.Contains(t, err.Error(), "ambiguous")
}

// ----- CountActiveAssignmentsForScope -----

func TestPasswordLoginRepo_CountActiveAssignmentsForScope(t *testing.T) {
	db := setupPasswordLoginDB(t)
	repo := repository.NewPasswordLoginRepository(db)
	ctx := context.Background()

	ep := newEndpoint("Verifier", "https://verifier.example.com/verify")
	require.NoError(t, repo.CreateEndpoint(ctx, ep))

	// No assignments yet
	count, err := repo.CountActiveAssignmentsForScope(ctx, strPtr("tenant-a"))
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	// Add an enabled assignment
	require.NoError(t, repo.CreateAssignment(ctx, newAssignment(strPtr("tenant-a"), ep.ID, true)))
	count, err = repo.CountActiveAssignmentsForScope(ctx, strPtr("tenant-a"))
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Disabled assignment does not count
	ep2 := newEndpoint("Verifier2", "https://v2.example.com/verify")
	require.NoError(t, repo.CreateEndpoint(ctx, ep2))
	require.NoError(t, repo.CreateAssignment(ctx, newAssignment(strPtr("tenant-a"), ep2.ID, false)))
	count, err = repo.CountActiveAssignmentsForScope(ctx, strPtr("tenant-a"))
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "disabled assignment must not increment count")
}

func TestPasswordLoginRepo_CountActiveAssignmentsForScope_Global(t *testing.T) {
	db := setupPasswordLoginDB(t)
	repo := repository.NewPasswordLoginRepository(db)
	ctx := context.Background()

	ep := newEndpoint("Global Verifier", "https://global.example.com/verify")
	require.NoError(t, repo.CreateEndpoint(ctx, ep))
	require.NoError(t, repo.CreateAssignment(ctx, newAssignment(nil, ep.ID, true)))

	count, err := repo.CountActiveAssignmentsForScope(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Tenant-specific scope must not bleed into global count
	count, err = repo.CountActiveAssignmentsForScope(ctx, strPtr("tenant-a"))
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}
