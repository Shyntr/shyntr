package repository_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/repository"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// 32-byte key satisfying AES-256 requirement.
var testLDAPAppSecret = []byte("test-secret-key-must-be-32bytes!")

func setupLDAPRepoTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbName := filepath.Join(t.TempDir(), fmt.Sprintf("%s.db", t.Name()))
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.LDAPConnectionGORM{}))
	return db
}

func TestLDAPConnectionRepository_Create_FailsOnEmptyTenant(t *testing.T) {
	t.Parallel()
	db := setupLDAPRepoTestDB(t)
	repo := repository.NewLDAPConnectionRepository(db, testLDAPAppSecret)
	ctx := context.Background()

	conn := &model.LDAPConnection{
		TenantID:  "", // empty tenant
		Name:      "Corp AD",
		ServerURL: "ldaps://ldap.corp.example.com:636",
		BaseDN:    "dc=corp,dc=example,dc=com",
	}

	err := repo.Create(ctx, conn)
	require.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrLDAPConnectionTenantRequired)
}

func TestLDAPConnectionRepository_Create_FailsOnNil(t *testing.T) {
	t.Parallel()
	db := setupLDAPRepoTestDB(t)
	repo := repository.NewLDAPConnectionRepository(db, testLDAPAppSecret)
	ctx := context.Background()

	err := repo.Create(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil")
}

func TestLDAPConnectionRepository_CreateAndGetByTenantAndID(t *testing.T) {
	t.Parallel()
	db := setupLDAPRepoTestDB(t)
	repo := repository.NewLDAPConnectionRepository(db, testLDAPAppSecret)
	ctx := context.Background()

	conn := &model.LDAPConnection{
		TenantID:     "tnt_ldap_01",
		Name:         "Corporate AD",
		ServerURL:    "ldaps://ldap.corp.example.com:636",
		BindDN:       "cn=svc,dc=corp,dc=example,dc=com",
		BindPassword: "s3cr3t",
		BaseDN:       "dc=corp,dc=example,dc=com",
		Active:       true,
	}

	err := repo.Create(ctx, conn)
	require.NoError(t, err)
	require.NotEmpty(t, conn.ID, "BeforeCreate hook must set ID")

	fetched, err := repo.GetByTenantAndID(ctx, "tnt_ldap_01", conn.ID)
	require.NoError(t, err)
	assert.Equal(t, conn.TenantID, fetched.TenantID)
	assert.Equal(t, conn.Name, fetched.Name)
	assert.Equal(t, conn.ServerURL, fetched.ServerURL)
	assert.Equal(t, "s3cr3t", fetched.BindPassword, "BindPassword must round-trip through AES-256-GCM")
}

func TestLDAPConnectionRepository_BindPasswordNeverStoredPlaintext(t *testing.T) {
	t.Parallel()
	db := setupLDAPRepoTestDB(t)
	repo := repository.NewLDAPConnectionRepository(db, testLDAPAppSecret)
	ctx := context.Background()

	conn := &model.LDAPConnection{
		TenantID:     "tnt_ldap_02",
		Name:         "AD",
		ServerURL:    "ldap://ldap.example.com",
		BindPassword: "plaintext-secret",
		BaseDN:       "dc=example,dc=com",
	}
	require.NoError(t, repo.Create(ctx, conn))

	// Read the raw GORM model directly to verify ciphertext is not plaintext.
	var raw models.LDAPConnectionGORM
	require.NoError(t, db.Where("id = ?", conn.ID).First(&raw).Error)
	assert.NotEqual(t, "plaintext-secret", string(raw.BindPasswordEncrypted),
		"BindPasswordEncrypted must not be the plaintext password")
	assert.NotEmpty(t, raw.BindPasswordEncrypted,
		"BindPasswordEncrypted must be populated when password is set")
}

func TestLDAPConnectionRepository_TenantIsolation(t *testing.T) {
	t.Parallel()
	db := setupLDAPRepoTestDB(t)
	repo := repository.NewLDAPConnectionRepository(db, testLDAPAppSecret)
	ctx := context.Background()

	connA := &model.LDAPConnection{
		TenantID:  "tnt_A",
		Name:      "Dir A",
		ServerURL: "ldap://a.example.com",
		BaseDN:    "dc=a,dc=example,dc=com",
	}
	connB := &model.LDAPConnection{
		TenantID:  "tnt_B",
		Name:      "Dir B",
		ServerURL: "ldap://b.example.com",
		BaseDN:    "dc=b,dc=example,dc=com",
	}
	require.NoError(t, repo.Create(ctx, connA))
	require.NoError(t, repo.Create(ctx, connB))

	// Tenant B cannot access tenant A's connection.
	_, err := repo.GetByTenantAndID(ctx, "tnt_B", connA.ID)
	assert.Error(t, err, "cross-tenant GetByTenantAndID must fail")
	assert.ErrorIs(t, err, repository.ErrLDAPConnectionNotFound)

	// Tenant A cannot delete tenant B's connection.
	err = repo.Delete(ctx, "tnt_A", connB.ID)
	assert.Error(t, err, "cross-tenant Delete must fail")
	assert.ErrorIs(t, err, repository.ErrLDAPConnectionNotFound)

	// Tenant A cannot update tenant B's connection.
	connB.Name = "pwned"
	connB.TenantID = "tnt_A"
	err = repo.Update(ctx, connB)
	assert.Error(t, err, "cross-tenant Update must fail")
	assert.ErrorIs(t, err, repository.ErrLDAPConnectionNotFound)

	fetched, fetchErr := repo.GetByTenantAndID(ctx, "tnt_B", connB.ID)
	require.NoError(t, fetchErr)
	assert.Equal(t, "Dir B", fetched.Name)
	assert.Equal(t, "tnt_B", fetched.TenantID)
}

func TestLDAPConnectionRepository_Update(t *testing.T) {
	t.Parallel()
	db := setupLDAPRepoTestDB(t)
	repo := repository.NewLDAPConnectionRepository(db, testLDAPAppSecret)
	ctx := context.Background()

	conn := &model.LDAPConnection{
		TenantID:     "tnt_upd",
		Name:         "Old Name",
		ServerURL:    "ldap://old.example.com",
		BindPassword: "oldpass",
		BaseDN:       "dc=example,dc=com",
	}
	require.NoError(t, repo.Create(ctx, conn))

	conn.Name = "New Name"
	conn.BindPassword = "newpass"
	require.NoError(t, repo.Update(ctx, conn))

	updated, err := repo.GetByTenantAndID(ctx, "tnt_upd", conn.ID)
	require.NoError(t, err)
	assert.Equal(t, "New Name", updated.Name)
	assert.Equal(t, "newpass", updated.BindPassword, "updated BindPassword must decrypt correctly")
}

func TestLDAPConnectionRepository_ListByTenant(t *testing.T) {
	t.Parallel()
	db := setupLDAPRepoTestDB(t)
	repo := repository.NewLDAPConnectionRepository(db, testLDAPAppSecret)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		require.NoError(t, repo.Create(ctx, &model.LDAPConnection{
			TenantID:  "tnt_list",
			Name:      fmt.Sprintf("Dir %d", i),
			ServerURL: fmt.Sprintf("ldap://dir%d.example.com", i),
			BaseDN:    "dc=example,dc=com",
		}))
	}
	// Extra connection for a different tenant — must not appear in results.
	require.NoError(t, repo.Create(ctx, &model.LDAPConnection{
		TenantID:  "tnt_other",
		Name:      "Other",
		ServerURL: "ldap://other.example.com",
		BaseDN:    "dc=other,dc=com",
	}))

	list, err := repo.ListByTenant(ctx, "tnt_list")
	require.NoError(t, err)
	assert.Len(t, list, 3, "ListByTenant must return only the requested tenant's connections")
}

func TestLDAPConnectionRepository_ListByTenant_RequiresTenant(t *testing.T) {
	t.Parallel()
	db := setupLDAPRepoTestDB(t)
	repo := repository.NewLDAPConnectionRepository(db, testLDAPAppSecret)

	list, err := repo.ListByTenant(context.Background(), "")
	require.Error(t, err)
	assert.Nil(t, list)
	assert.ErrorIs(t, err, repository.ErrLDAPConnectionTenantRequired)
}

func TestLDAPConnectionRepository_GetConnectionCount_RequiresTenant(t *testing.T) {
	t.Parallel()
	db := setupLDAPRepoTestDB(t)
	repo := repository.NewLDAPConnectionRepository(db, testLDAPAppSecret)

	count, err := repo.GetConnectionCount(context.Background(), "")
	require.Error(t, err)
	assert.Zero(t, count)
	assert.ErrorIs(t, err, repository.ErrLDAPConnectionTenantRequired)
}

func TestLDAPConnectionRepository_AnonymousBind(t *testing.T) {
	t.Parallel()
	db := setupLDAPRepoTestDB(t)
	repo := repository.NewLDAPConnectionRepository(db, testLDAPAppSecret)
	ctx := context.Background()

	conn := &model.LDAPConnection{
		TenantID:     "tnt_anon",
		Name:         "Anon LDAP",
		ServerURL:    "ldap://anon.example.com",
		BindPassword: "", // anonymous bind
		BaseDN:       "dc=example,dc=com",
	}
	require.NoError(t, repo.Create(ctx, conn))

	fetched, err := repo.GetByTenantAndID(ctx, "tnt_anon", conn.ID)
	require.NoError(t, err)
	assert.Equal(t, "", fetched.BindPassword, "anonymous bind must round-trip as empty string")

	var raw models.LDAPConnectionGORM
	require.NoError(t, db.Where("id = ?", conn.ID).First(&raw).Error)
	assert.Empty(t, raw.BindPasswordEncrypted, "anonymous bind must store nil ciphertext")
}

func TestLDAPConnectionRepository_ListActiveByTenant(t *testing.T) {
	t.Parallel()
	db := setupLDAPRepoTestDB(t)
	repo := repository.NewLDAPConnectionRepository(db, testLDAPAppSecret)
	ctx := context.Background()

	// 2 active for tenant-a
	connA1 := &model.LDAPConnection{
		TenantID:  "tnt_active_a",
		Name:      "Active 1",
		ServerURL: "ldap://a1.example.com",
		BaseDN:    "dc=example,dc=com",
		Active:    true,
	}
	connA2 := &model.LDAPConnection{
		TenantID:  "tnt_active_a",
		Name:      "Active 2",
		ServerURL: "ldap://a2.example.com",
		BaseDN:    "dc=example,dc=com",
		Active:    true,
	}
	// 1 inactive for tenant-a — create active then explicitly deactivate in DB
	connA3inactive := &model.LDAPConnection{
		TenantID:  "tnt_active_a",
		Name:      "Inactive",
		ServerURL: "ldap://a3.example.com",
		BaseDN:    "dc=example,dc=com",
		Active:    true, // will be deactivated below
	}
	// 1 active for tenant-b — must not appear in tenant-a results
	connB1 := &model.LDAPConnection{
		TenantID:  "tnt_active_b",
		Name:      "B Active",
		ServerURL: "ldap://b1.example.com",
		BaseDN:    "dc=b,dc=com",
		Active:    true,
	}

	require.NoError(t, repo.Create(ctx, connA1))
	require.NoError(t, repo.Create(ctx, connA2))
	require.NoError(t, repo.Create(ctx, connA3inactive))
	// Deactivate connA3inactive directly in the DB to bypass GORM zero-value default.
	require.NoError(t, db.Model(&models.LDAPConnectionGORM{}).
		Where("id = ?", connA3inactive.ID).
		Update("active", false).Error)
	require.NoError(t, repo.Create(ctx, connB1))

	// ListActiveByTenant for tenant-a must return exactly the 2 active records.
	listA, err := repo.ListActiveByTenant(ctx, "tnt_active_a")
	require.NoError(t, err)
	assert.Len(t, listA, 2, "must return only the 2 active connections for tenant-a")
	for _, c := range listA {
		assert.Equal(t, "tnt_active_a", c.TenantID)
		assert.True(t, c.Active, "all returned connections must be active")
	}

	// ListActiveByTenant for unknown tenant must return empty slice, nil error.
	listX, err := repo.ListActiveByTenant(ctx, "tnt_nonexistent")
	require.NoError(t, err)
	assert.Empty(t, listX, "must return empty slice for unknown tenant")
}

func TestLDAPConnectionRepository_ListActiveByTenant_EmptyTenant(t *testing.T) {
	t.Parallel()
	db := setupLDAPRepoTestDB(t)
	repo := repository.NewLDAPConnectionRepository(db, testLDAPAppSecret)

	list, err := repo.ListActiveByTenant(context.Background(), "")
	assert.Nil(t, list)
	assert.ErrorIs(t, err, repository.ErrLDAPConnectionTenantRequired)
}

func TestLDAPConnectionRepository_Update_BooleanFieldsPersistedWhenFalse(t *testing.T) {
	t.Parallel()
	db := setupLDAPRepoTestDB(t)
	repo := repository.NewLDAPConnectionRepository(db, testLDAPAppSecret)
	ctx := context.Background()

	// Create with StartTLS=true and TLSInsecureSkipVerify=true.
	conn := &model.LDAPConnection{
		TenantID:              "tnt_bool",
		Name:                  "Bool Test",
		ServerURL:             "ldaps://ldap.example.com:636",
		BaseDN:                "dc=example,dc=com",
		StartTLS:              true,
		TLSInsecureSkipVerify: true,
		Active:                true,
	}
	require.NoError(t, repo.Create(ctx, conn))

	// Update: toggle both booleans to false.
	conn.StartTLS = false
	conn.TLSInsecureSkipVerify = false
	require.NoError(t, repo.Update(ctx, conn))

	fetched, err := repo.GetByTenantAndID(ctx, "tnt_bool", conn.ID)
	require.NoError(t, err)
	assert.False(t, fetched.StartTLS, "StartTLS must be persisted as false after update")
	assert.False(t, fetched.TLSInsecureSkipVerify, "TLSInsecureSkipVerify must be persisted as false after update")
}

func TestLDAPConnectionRepository_Update_AttributeMappingRoundTrip(t *testing.T) {
	t.Parallel()
	db := setupLDAPRepoTestDB(t)
	repo := repository.NewLDAPConnectionRepository(db, testLDAPAppSecret)
	ctx := context.Background()

	// Create with an initial AttributeMapping that maps "sub" from "uid".
	conn := &model.LDAPConnection{
		TenantID:  "tnt_attrmap",
		Name:      "AttrMap Test",
		ServerURL: "ldap://ldap.example.com",
		BaseDN:    "dc=example,dc=com",
		Active:    true,
		AttributeMapping: map[string]model.AttributeMappingRule{
			"sub": {Source: "uid", Type: "string"},
		},
	}
	require.NoError(t, repo.Create(ctx, conn))

	// Update: change the "sub" mapping source from "uid" → "mail" and add a second rule.
	conn.AttributeMapping = map[string]model.AttributeMappingRule{
		"sub":   {Source: "mail", Type: "string"},
		"email": {Source: "mail", Type: "string"},
	}
	require.NoError(t, repo.Update(ctx, conn))

	fetched, err := repo.GetByTenantAndID(ctx, "tnt_attrmap", conn.ID)
	require.NoError(t, err)

	require.Len(t, fetched.AttributeMapping, 2, "AttributeMapping must contain exactly the two updated rules")
	assert.Equal(t, "mail", fetched.AttributeMapping["sub"].Source,
		"sub Source must be updated from uid to mail")
	assert.Equal(t, "string", fetched.AttributeMapping["sub"].Type,
		"sub Type must survive the update round-trip")
	assert.Equal(t, "mail", fetched.AttributeMapping["email"].Source,
		"email rule added during update must be present after read")
}

func TestLDAPConnectionRepository_ListActiveByTenant_BrokenDB(t *testing.T) {
	t.Parallel()
	db := setupLDAPRepoTestDB(t)
	repo := repository.NewLDAPConnectionRepository(db, testLDAPAppSecret)

	// Close the underlying connection to simulate a broken DB.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	_, err = repo.ListActiveByTenant(context.Background(), "any-tenant")
	assert.Error(t, err, "a broken DB must return an error")
}
