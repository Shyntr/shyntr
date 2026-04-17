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

	// Tenant B: SAML Success
	detailsSAML, _ := json.Marshal(map[string]interface{}{"protocol": "saml"})
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
	assert.Equal(t, int64(2), activity.Protocols["oidc"].Success) // aud1 and aud3
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
	assert.Equal(t, int64(3), activity2.Protocols["oidc"].Success) // aud1, aud3, aud5
}
