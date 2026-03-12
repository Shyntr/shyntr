package utils_test

import (
	"testing"

	"github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/entity"
	"github.com/stretchr/testify/assert"
)

func TestMapClaims_ZeroTrust_Isolation(t *testing.T) {
	subject := "user-123"
	userContext := map[string]interface{}{
		"tenant_id": "tenant-alpha",
		"idp":       "azure-ad",
		"login_claims": map[string]interface{}{
			"email":       "alice@shyntr.com",
			"department":  "Engineering",
			"salary_band": "L5",
			"title":       "Senior IAM Architect",
		},
		"some_random_injected_data": "malicious_payload",
	}

	grantedScopesEmailOnly := []*entity.Scope{
		{
			Name:   "email",
			Claims: []string{"email", "email_verified"},
		},
	}

	filteredClaimsA := utils.MapClaims(subject, userContext, grantedScopesEmailOnly)

	assert.Equal(t, subject, filteredClaimsA["sub"], "Subject must always be present")
	assert.Equal(t, "tenant-alpha", filteredClaimsA["tenant_id"], "System context must be preserved")

	assert.Equal(t, "alice@shyntr.com", filteredClaimsA["email"])

	_, hasSalary := filteredClaimsA["salary_band"]
	assert.False(t, hasSalary, "SECURITY REGRESSION: Sensitive data leaked without scope authorization!")

	_, hasDept := filteredClaimsA["department"]
	assert.False(t, hasDept, "SECURITY REGRESSION: Unrequested claim mapped to output!")

	_, hasMalicious := filteredClaimsA["some_random_injected_data"]
	assert.False(t, hasMalicious, "SECURITY REGRESSION: Unmapped root context leaked!")

	grantedScopesHR := []*entity.Scope{
		{
			Name:   "email",
			Claims: []string{"email"},
		},
		{
			Name:   "hr_data",
			Claims: []string{"department", "salary_band", "title"},
		},
	}

	filteredClaimsB := utils.MapClaims(subject, userContext, grantedScopesHR)

	assert.Equal(t, "L5", filteredClaimsB["salary_band"], "Authorized sensitive data should be present")
	assert.Equal(t, "Engineering", filteredClaimsB["department"])
}
