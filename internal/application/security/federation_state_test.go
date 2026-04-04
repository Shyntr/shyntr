package security

import (
	"context"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/stretchr/testify/require"
)

func testConfig() *config.Config {
	return &config.Config{
		AppSecret: "12345678901234567890123456789012",
	}
}

func TestFederationState_IssueAndVerify_Success(t *testing.T) {
	now := time.Date(2026, 3, 29, 10, 0, 0, 0, time.UTC)
	provider := NewFederationStateProviderWithClock(testConfig(), func() time.Time { return now })

	token, err := provider.Issue(context.Background(), IssueFederationStateInput{
		Action:         FederationActionOIDCLogin,
		TenantID:       "default",
		LoginChallenge: "lc_123",
		ConnectionID:   "conn_456",
		CSRFToken:      "csrf_789",
		TTL:            10 * time.Minute,
	})
	require.NoError(t, err)
	require.NotEmpty(t, token)

	payload, err := provider.Verify(context.Background(), token, VerifyFederationStateInput{
		ExpectedAction: FederationActionOIDCLogin,
		ExpectedTenant: "default",
		CSRFToken:      "csrf_789",
		Now:            now.Add(1 * time.Minute),
	})
	require.NoError(t, err)
	require.Equal(t, "default", payload.TenantID)
	require.Equal(t, "lc_123", payload.LoginChallenge)
	require.Equal(t, "conn_456", payload.ConnectionID)
	require.Equal(t, FederationActionOIDCLogin, payload.Action)
}

func TestFederationState_Verify_Expired(t *testing.T) {
	now := time.Date(2026, 3, 29, 10, 0, 0, 0, time.UTC)
	provider := NewFederationStateProviderWithClock(testConfig(), func() time.Time { return now })

	token, err := provider.Issue(context.Background(), IssueFederationStateInput{
		Action:         FederationActionSAMLLogin,
		TenantID:       "default",
		LoginChallenge: "lc_123",
		ConnectionID:   "conn_456",
		CSRFToken:      "csrf_789",
		TTL:            1 * time.Minute,
	})
	require.NoError(t, err)

	_, err = provider.Verify(context.Background(), token, VerifyFederationStateInput{
		ExpectedAction: FederationActionSAMLLogin,
		ExpectedTenant: "default",
		CSRFToken:      "csrf_789",
		Now:            now.Add(2 * time.Minute),
	})
	require.ErrorIs(t, err, ErrExpiredFederationState)
}

func TestFederationState_Verify_CSRFMismatch(t *testing.T) {
	now := time.Date(2026, 3, 29, 10, 0, 0, 0, time.UTC)
	provider := NewFederationStateProviderWithClock(testConfig(), func() time.Time { return now })

	token, err := provider.Issue(context.Background(), IssueFederationStateInput{
		Action:         FederationActionOIDCLogin,
		TenantID:       "default",
		LoginChallenge: "lc_123",
		ConnectionID:   "conn_456",
		CSRFToken:      "csrf_789",
		TTL:            10 * time.Minute,
	})
	require.NoError(t, err)

	_, err = provider.Verify(context.Background(), token, VerifyFederationStateInput{
		ExpectedAction: FederationActionOIDCLogin,
		ExpectedTenant: "default",
		CSRFToken:      "csrf_wrong",
		Now:            now.Add(1 * time.Minute),
	})
	require.ErrorIs(t, err, ErrCSRFMismatch)
}

func TestFederationState_Verify_TenantMismatch(t *testing.T) {
	now := time.Date(2026, 3, 29, 10, 0, 0, 0, time.UTC)
	provider := NewFederationStateProviderWithClock(testConfig(), func() time.Time { return now })

	token, err := provider.Issue(context.Background(), IssueFederationStateInput{
		Action:         FederationActionOIDCLogin,
		TenantID:       "tenant-a",
		LoginChallenge: "lc_123",
		ConnectionID:   "conn_456",
		CSRFToken:      "csrf_789",
		TTL:            10 * time.Minute,
	})
	require.NoError(t, err)

	_, err = provider.Verify(context.Background(), token, VerifyFederationStateInput{
		ExpectedAction: FederationActionOIDCLogin,
		ExpectedTenant: "tenant-b",
		CSRFToken:      "csrf_789",
		Now:            now.Add(1 * time.Minute),
	})
	require.ErrorIs(t, err, ErrTenantMismatch)
}
