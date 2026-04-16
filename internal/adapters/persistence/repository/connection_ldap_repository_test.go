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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// 32-byte key satisfying AES-256 requirement.
var testLDAPAppSecret = []byte("test-secret-key-must-be-32bytes!")

func setupLDAPRepoTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbName := fmt.Sprintf("file:ldap_repo_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.LDAPConnectionGORM{}))
	return db
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
	assert.Equal(t, "ldap connection not found", err.Error())

	// Tenant A cannot delete tenant B's connection.
	err = repo.Delete(ctx, "tnt_A", connB.ID)
	assert.Error(t, err, "cross-tenant Delete must fail")
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
