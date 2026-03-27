package usecase_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSAMLRepo struct {
	DeleteFunc func(ctx context.Context, tenantID, id string) error
	UpdateFunc func(ctx context.Context, client *model.SAMLClient) error
}

func (m *mockSAMLRepo) Create(ctx context.Context, client *model.SAMLClient) error { return nil }
func (m *mockSAMLRepo) GetByID(ctx context.Context, tenantID, id string) (*model.SAMLClient, error) {
	return nil, nil
}
func (m *mockSAMLRepo) GetByEntityID(ctx context.Context, entityID string) (*model.SAMLClient, error) {
	return nil, nil
}
func (m *mockSAMLRepo) GetByEntity(entityID string) (*model.SAMLClient, error) { return nil, nil }
func (m *mockSAMLRepo) GetClientCount(ctx context.Context, tenantID string) (int64, error) {
	return 0, nil
}
func (m *mockSAMLRepo) GetByTenantAndEntityID(ctx context.Context, tenantID, entityID string) (*model.SAMLClient, error) {
	return nil, nil
}
func (m *mockSAMLRepo) ListByTenant(ctx context.Context, tenantID string) ([]*model.SAMLClient, error) {
	return nil, nil
}
func (m *mockSAMLRepo) List(ctx context.Context) ([]*model.SAMLClient, error) { return nil, nil }

func (m *mockSAMLRepo) Delete(ctx context.Context, tenantID, id string) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, tenantID, id)
	}
	return nil
}

func (m *mockSAMLRepo) Update(ctx context.Context, client *model.SAMLClient) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(ctx, client)
	}
	return nil
}

type mockOutboundGuard struct{}

func (m *mockOutboundGuard) ValidateURL(ctx context.Context, tenantID string, target model.OutboundTargetType, rawURL string) (*url.URL, *model.OutboundPolicy, error) {
	u, _ := url.Parse(rawURL)
	return u, &model.OutboundPolicy{
		Enabled:               true,
		AllowedSchemes:        []string{"http", "https"},
		RequestTimeoutSeconds: 5,
		MaxResponseBytes:      2 << 20,
	}, nil
}

func (m *mockOutboundGuard) NewHTTPClient(ctx context.Context, tenantID string, target model.OutboundTargetType, policy *model.OutboundPolicy) *http.Client {
	return &http.Client{}
}

type mockAuditLogger struct {
	LoggedTenantID string
	LoggedAction   string
	LoggedIP       string
}

func (m *mockAuditLogger) Log(tenantID, subject, action, actorIP, userAgent string, metadata map[string]interface{}) {
	m.LoggedTenantID = tenantID
	m.LoggedAction = action
	m.LoggedIP = actorIP
}

func TestSAMLClientUseCase_DeleteClient(t *testing.T) {
	t.Parallel()

	mockRepo := &mockSAMLRepo{}
	mockAudit := &mockAuditLogger{}

	uc := usecase.NewSAMLClientUseCase(mockRepo, nil, mockAudit, &mockOutboundGuard{})

	tenantID := "tnt_saml_01"
	clientID := "client_123"
	actorIP := "192.168.1.15"
	userAgent := "shyntr-admin-ui"

	mockRepo.DeleteFunc = func(ctx context.Context, tID, id string) error {
		assert.Equal(t, tenantID, tID)
		assert.Equal(t, clientID, id)
		return nil
	}

	err := uc.DeleteClient(context.Background(), tenantID, clientID, actorIP, userAgent)
	require.NoError(t, err)

	assert.Equal(t, "management.client.saml.delete", mockAudit.LoggedAction, "Audit log must explicitly record the delete action")
	assert.Equal(t, tenantID, mockAudit.LoggedTenantID, "Audit log must be bounded to the correct tenant")
	assert.Equal(t, actorIP, mockAudit.LoggedIP)
}

func TestSAMLClientUseCase_DeleteClient_RepoFailure(t *testing.T) {
	t.Parallel()

	mockRepo := &mockSAMLRepo{}
	mockAudit := &mockAuditLogger{}
	uc := usecase.NewSAMLClientUseCase(mockRepo, nil, mockAudit, &mockOutboundGuard{})

	expectedErr := errors.New("database connection lost")
	mockRepo.DeleteFunc = func(ctx context.Context, tID, id string) error {
		return expectedErr
	}

	err := uc.DeleteClient(context.Background(), "tnt", "client_1", "127.0.0.1", "ua")

	assert.ErrorIs(t, err, expectedErr)
	assert.Empty(t, mockAudit.LoggedAction, "Should not emit success audit log if repo deletion fails")
}

func TestSAMLClientUseCase_UpdateClient_ValidationFailure(t *testing.T) {
	t.Parallel()
	mockRepo := &mockSAMLRepo{}
	mockAudit := &mockAuditLogger{}
	uc := usecase.NewSAMLClientUseCase(mockRepo, nil, mockAudit, &mockOutboundGuard{})

	invalidClient := &model.SAMLClient{
		ID:       "client_1",
		TenantID: "tnt_1",
		EntityID: "",
	}

	err := uc.UpdateClient(context.Background(), invalidClient, "127.0.0.1", "ua")
	assert.Error(t, err, "Update MUST fail before hitting the repository if validation fails")
	assert.Empty(t, mockAudit.LoggedAction, "Audit log must not be written for validation failures during update")
}
