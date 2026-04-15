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
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupAuthRequestRepoTestDB(t *testing.T) *gorm.DB {
	dbName := fmt.Sprintf("file:auth_request_repo_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, db.AutoMigrate(&models.LoginRequestGORM{}))
	return db
}

func TestAuthRequestRepository_GetAuthenticatedLoginRequestBySubject_IsTenantScoped(t *testing.T) {
	t.Parallel()

	db := setupAuthRequestRepoTestDB(t)
	repo := repository.NewAuthRequestRepository(db)
	ctx := context.Background()

	require.NoError(t, repo.SaveLoginRequest(ctx, &model.LoginRequest{
		ID:            "login-a",
		TenantID:      "tenant-a",
		ClientID:      "client-a",
		Subject:       "shared-subject",
		Authenticated: true,
		Active:        true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}))
	require.NoError(t, repo.SaveLoginRequest(ctx, &model.LoginRequest{
		ID:            "login-b",
		TenantID:      "tenant-b",
		ClientID:      "client-b",
		Subject:       "shared-subject",
		Authenticated: true,
		Active:        true,
		CreatedAt:     time.Now().Add(time.Second),
		UpdatedAt:     time.Now().Add(time.Second),
	}))

	login, err := repo.GetAuthenticatedLoginRequestBySubject(ctx, "tenant-a", "shared-subject")
	require.NoError(t, err)
	require.NotNil(t, login)
	require.Equal(t, "tenant-a", login.TenantID)
	require.Equal(t, "login-a", login.ID)
}
