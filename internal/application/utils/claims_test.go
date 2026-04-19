package utils_test

import (
	"testing"

	"github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/model"
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

	grantedScopesEmailOnly := []*model.Scope{
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

	grantedScopesHR := []*model.Scope{
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

// ---------------------------------------------------------------------------
// Regression: Gap B — standard OIDC scopes allow well-known claims even when
// scope.Claims is empty (scopeToClaims fallback).
// ---------------------------------------------------------------------------

func TestMapClaims_StandardScope_EmailClaimWithEmptyScopeClaims(t *testing.T) {
	// Granting the "email" scope must allow "email" and "email_verified" even
	// when the database scope record has no explicit Claims list.
	// Before the fix, scopeToClaims was never consulted, so the claim was
	// silently dropped.
	subject := "user-42"
	ctx := map[string]interface{}{
		"login_claims": map[string]interface{}{
			"email":          "bob@example.com",
			"email_verified": true,
		},
	}

	emailScopeEmptyClaims := []*model.Scope{
		{Name: "email", Claims: nil}, // DB record has no explicit claim list
	}

	claims := utils.MapClaims(subject, ctx, emailScopeEmptyClaims)

	assert.Equal(t, "bob@example.com", claims["email"],
		"email scope must release email claim via standard mapping even with empty scope.Claims")
	assert.Equal(t, true, claims["email_verified"],
		"email scope must release email_verified via standard mapping")
}

func TestMapClaims_StandardScope_ProfileClaimWithEmptyScopeClaims(t *testing.T) {
	subject := "user-42"
	ctx := map[string]interface{}{
		"login_claims": map[string]interface{}{
			"name":       "Bob Builder",
			"given_name": "Bob",
			"salary":     "confidential", // not in profile scope
		},
	}

	profileScopeEmptyClaims := []*model.Scope{
		{Name: "profile", Claims: nil},
	}

	claims := utils.MapClaims(subject, ctx, profileScopeEmptyClaims)

	assert.Equal(t, "Bob Builder", claims["name"])
	assert.Equal(t, "Bob", claims["given_name"])
	_, hasSalary := claims["salary"]
	assert.False(t, hasSalary, "SECURITY REGRESSION: non-profile claim leaked via standard mapping")
}

func TestMapClaims_StandardScope_DoesNotLeakAcrossScopes(t *testing.T) {
	// Granting "email" must not release "address" or "phone" claims.
	subject := "user-42"
	ctx := map[string]interface{}{
		"login_claims": map[string]interface{}{
			"email":        "bob@example.com",
			"address":      "123 Main St",
			"phone_number": "+1555000",
		},
	}

	emailScopeOnly := []*model.Scope{
		{Name: "email", Claims: nil},
	}

	claims := utils.MapClaims(subject, ctx, emailScopeOnly)

	assert.Equal(t, "bob@example.com", claims["email"])
	_, hasAddress := claims["address"]
	assert.False(t, hasAddress, "SECURITY REGRESSION: address leaked when only email scope granted")
	_, hasPhone := claims["phone_number"]
	assert.False(t, hasPhone, "SECURITY REGRESSION: phone_number leaked when only email scope granted")
}

func TestMapClaims_ExplicitScopeClaimsAndStandardClaimsMerge(t *testing.T) {
	// scope.Claims and scopeToClaims must both contribute to allowedKeys.
	// A custom claim registered via scope.Claims must also be allowed alongside
	// the standard OIDC claims from the same scope name.
	subject := "user-42"
	ctx := map[string]interface{}{
		"login_claims": map[string]interface{}{
			"email":          "bob@example.com",
			"email_verified": false,
			"custom_claim":   "custom_value",
		},
	}

	emailScopeWithCustomClaim := []*model.Scope{
		{Name: "email", Claims: []string{"custom_claim"}},
	}

	claims := utils.MapClaims(subject, ctx, emailScopeWithCustomClaim)

	assert.Equal(t, "bob@example.com", claims["email"],
		"standard email claim must be allowed via scopeToClaims")
	assert.Equal(t, false, claims["email_verified"],
		"standard email_verified claim must be allowed via scopeToClaims")
	assert.Equal(t, "custom_value", claims["custom_claim"],
		"explicit scope.Claims entry must still be allowed")
}
