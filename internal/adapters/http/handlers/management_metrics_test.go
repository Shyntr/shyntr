package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/stretchr/testify/assert"
)

func TestGetAuthActivity(t *testing.T) {
	r, db := setupManagementAPI(t)
	db.Exec("DELETE FROM audit_logs")

	// Create some audit logs for multiple tenants
	tenantA := "tenant-a"
	tenantB := "tenant-b"
	now := time.Now()

	// Tenant A: OIDC Success
	detailsOIDC, _ := json.Marshal(map[string]interface{}{"protocol": "oidc"})
	db.Create(&models.AuditLogGORM{
		ID:        "aud1",
		TenantID:  tenantA,
		Action:    "auth.login.accept",
		Details:   detailsOIDC,
		CreatedAt: now.Add(-10 * time.Minute),
	})

	// Tenant B: SAML provider success in an OIDC login flow
	detailsSAML, _ := json.Marshal(map[string]interface{}{"protocol": "oidc", "provider_type": "saml"})
	db.Create(&models.AuditLogGORM{
		ID:        "aud2",
		TenantID:  tenantB,
		Action:    "provider.login.success",
		Details:   detailsSAML,
		CreatedAt: now.Add(-20 * time.Minute),
	})

	// Tenant A: LDAP Success (via provider_type)
	detailsLDAP, _ := json.Marshal(map[string]interface{}{"protocol": "oidc", "provider_type": "ldap"})
	db.Create(&models.AuditLogGORM{
		ID:        "aud3",
		TenantID:  tenantA,
		Action:    "provider.login.success",
		Details:   detailsLDAP,
		CreatedAt: now.Add(-30 * time.Minute),
	})

	// Tenant B: LDAP Failure
	db.Create(&models.AuditLogGORM{
		ID:        "aud4",
		TenantID:  tenantB,
		Action:    "auth.ldap.bind.fail",
		CreatedAt: now.Add(-40 * time.Minute),
	})

	// Old log (outside 1h range)
	db.Create(&models.AuditLogGORM{
		ID:        "aud5",
		TenantID:  tenantA,
		Action:    "auth.login.accept",
		Details:   detailsOIDC,
		CreatedAt: now.Add(-2 * time.Hour),
	})

	// Test 1h range without tenant_id
	req, _ := http.NewRequest("GET", "/admin/management/dashboard/auth-activity?range=1h", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var activity model.AuthActivity
	err := json.Unmarshal(w.Body.Bytes(), &activity)
	assert.NoError(t, err)

	assert.Equal(t, "1h", activity.Range)
	assert.Equal(t, int64(3), activity.Protocols["oidc"].Success) // aud1, aud2, and aud3
	assert.Equal(t, int64(1), activity.Protocols["saml"].Success) // aud2
	assert.Equal(t, int64(1), activity.Protocols["ldap"].Success) // aud3
	assert.Equal(t, int64(1), activity.Protocols["ldap"].Failure) // aud4

	assert.Equal(t, int64(3), activity.Totals.Success) // aud1, aud2, aud3 aggregated across tenants
	assert.Equal(t, int64(1), activity.Totals.Failure) // aud4

	// Test 24h range without tenant_id
	req2, _ := http.NewRequest("GET", "/admin/management/dashboard/auth-activity?range=24h", nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	var activity2 model.AuthActivity
	json.Unmarshal(w2.Body.Bytes(), &activity2)
	assert.Equal(t, int64(4), activity2.Protocols["oidc"].Success) // aud1, aud2, aud3, aud5
}

func TestGetAuthFailures(t *testing.T) {
	r, db := setupManagementAPI(t)
	db.Exec("DELETE FROM audit_logs")

	// Create some failure audit logs
	tenantA := "tenant-a"
	now := time.Now()

	// LDAP Invalid Credentials
	detailsLDAP, _ := json.Marshal(map[string]interface{}{"protocol": "oidc", "provider_type": "ldap", "reason": "invalid credentials"})
	db.Create(&models.AuditLogGORM{
		ID:        "f1",
		TenantID:  tenantA,
		Action:    "auth.ldap.bind.fail",
		Details:   detailsLDAP,
		CreatedAt: now.Add(-10 * time.Minute),
	})

	// OIDC Invalid Request
	detailsOIDC, _ := json.Marshal(map[string]interface{}{"protocol": "oidc", "error_name": "invalid_request"})
	db.Create(&models.AuditLogGORM{
		ID:        "f2",
		TenantID:  tenantA,
		Action:    "auth.login.reject",
		Details:   detailsOIDC,
		CreatedAt: now.Add(-20 * time.Minute),
	})

	// SAML Unknown Failure
	detailsSAML, _ := json.Marshal(map[string]interface{}{"protocol": "saml", "error_name": "unknown_error"})
	db.Create(&models.AuditLogGORM{
		ID:        "f3",
		TenantID:  tenantA,
		Action:    "auth.login.reject",
		Details:   detailsSAML,
		CreatedAt: now.Add(-30 * time.Minute),
	})

	// Test 1h range
	req, _ := http.NewRequest("GET", "/admin/management/dashboard/auth-failures?range=1h", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var failures model.AuthFailures
	err := json.Unmarshal(w.Body.Bytes(), &failures)
	assert.NoError(t, err)

	assert.Equal(t, int64(3), failures.Totals.Failure)
	assert.Equal(t, int64(2), failures.Protocols["oidc"].Failure)
	assert.Equal(t, int64(1), failures.Protocols["ldap"].Failure)
	assert.Equal(t, int64(1), failures.Protocols["saml"].Failure)

	assert.Contains(t, []string{"invalid_request", "invalid_credentials"}, failures.Protocols["oidc"].TopReason)
	assert.Equal(t, "invalid_credentials", failures.Protocols["ldap"].TopReason)
	assert.Equal(t, "unknown", failures.Protocols["saml"].TopReason)

	// Verify reasons list
	reasons := make(map[string]int64)
	for _, r := range failures.Reasons {
		reasons[r.Key] = r.Count
	}
	assert.Equal(t, int64(1), reasons["invalid_credentials"])
	assert.Equal(t, int64(1), reasons["invalid_request"])
	assert.Equal(t, int64(1), reasons["unknown"])
}

func TestGetHealthSummary(t *testing.T) {
	r, _ := setupManagementAPI(t)

	req, _ := http.NewRequest("GET", "/admin/management/dashboard/health-summary", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var summary model.HealthSummary
	err := json.Unmarshal(w.Body.Bytes(), &summary)
	assert.NoError(t, err)

	assert.Equal(t, "ok", summary.Status)
	assert.Equal(t, "ok", summary.Checks.Database)
	assert.Equal(t, "ok", summary.Checks.SigningKeys)
	assert.Equal(t, "ok", summary.Checks.Migrations)
}

func TestGetRoutingInsights(t *testing.T) {
	r, db := setupManagementAPI(t)
	db.Exec("DELETE FROM audit_logs")

	now := time.Now()

	// OIDC -> OIDC
	details1, _ := json.Marshal(map[string]interface{}{"protocol": "oidc", "provider_type": "oidc"})
	db.Create(&models.AuditLogGORM{ID: "r1", Action: "provider.login.success", Details: details1, CreatedAt: now.Add(-5 * time.Minute)})

	// OIDC -> SAML
	details2, _ := json.Marshal(map[string]interface{}{"protocol": "oidc", "provider_type": "saml"})
	db.Create(&models.AuditLogGORM{ID: "r2", Action: "provider.login.success", Details: details2, CreatedAt: now.Add(-10 * time.Minute)})

	// SAML -> OIDC
	details3, _ := json.Marshal(map[string]interface{}{"protocol": "saml", "provider_type": "oidc"})
	db.Create(&models.AuditLogGORM{ID: "r3", Action: "provider.login.success", Details: details3, CreatedAt: now.Add(-15 * time.Minute)})

	// OIDC -> LDAP
	details4, _ := json.Marshal(map[string]interface{}{"protocol": "oidc", "provider_type": "ldap"})
	db.Create(&models.AuditLogGORM{ID: "r4", Action: "provider.login.success", Details: details4, CreatedAt: now.Add(-20 * time.Minute)})

	// Test GET /admin/management/dashboard/routing-insights
	req, _ := http.NewRequest("GET", "/admin/management/dashboard/routing-insights?range=1h", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var insights model.RoutingInsights
	err := json.Unmarshal(w.Body.Bytes(), &insights)
	assert.NoError(t, err)

	assert.Equal(t, int64(1), insights.Totals.SameProtocol) // oidc -> oidc
	assert.Equal(t, int64(3), insights.Totals.Routed)       // oidc->saml, saml->oidc, oidc->ldap

	// Check transitions
	transitions := make(map[string]int64)
	for _, t := range insights.Transitions {
		transitions[t.From+"->"+t.To] = t.Count
	}
	assert.Equal(t, int64(1), transitions["oidc->oidc"])
	assert.Equal(t, int64(1), transitions["oidc->saml"])
	assert.Equal(t, int64(1), transitions["saml->oidc"])
	assert.Equal(t, int64(1), transitions["oidc->ldap"])
}
