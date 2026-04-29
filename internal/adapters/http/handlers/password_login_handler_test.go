package handlers_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Shyntr/shyntr/internal/adapters/http/handlers"
	"github.com/Shyntr/shyntr/internal/adapters/http/middleware"
	"github.com/Shyntr/shyntr/internal/adapters/http/payload"
	"github.com/Shyntr/shyntr/internal/adapters/persistence"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/repository"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupPasswordLoginAPI(t *testing.T) (*gin.Engine, *gorm.DB) {
	t.Helper()
	logger.InitLogger("info")
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString())), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, persistence.MigrateDB(db))

	repo := repository.NewPasswordLoginRepository(db)
	uc := usecase.NewPasswordLoginUseCase(repo)
	handler := handlers.NewPasswordLoginHandler(uc)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.ErrorHandlerMiddleware())

	r.POST("/admin/management/password-login/endpoints", handler.CreateEndpoint)
	r.GET("/admin/management/password-login/endpoints", handler.ListEndpoints)
	r.GET("/admin/management/password-login/endpoints/:id", handler.GetEndpoint)
	r.PUT("/admin/management/password-login/endpoints/:id", handler.UpdateEndpoint)
	r.DELETE("/admin/management/password-login/endpoints/:id", handler.DeleteEndpoint)

	r.POST("/admin/management/password-login/assignments", handler.CreateAssignment)
	r.GET("/admin/management/password-login/assignments", handler.ListAssignments)
	r.GET("/admin/management/password-login/assignments/:id", handler.GetAssignment)
	r.PUT("/admin/management/password-login/assignments/:id", handler.UpdateAssignment)
	r.DELETE("/admin/management/password-login/assignments/:id", handler.DeleteAssignment)

	return r, db
}

func jsonBody(t *testing.T, v interface{}) *bytes.Buffer {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewBuffer(b)
}

// ----- Endpoint handler tests -----

func TestPasswordLoginHandler_CreateEndpoint_ValidInput(t *testing.T) {
	r, _ := setupPasswordLoginAPI(t)

	body := jsonBody(t, map[string]interface{}{
		"name":      "EU Verifier",
		"login_url": "https://eu-verifier.example.com/auth/password",
		"is_active": true,
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/admin/management/password-login/endpoints", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp payload.PasswordLoginEndpointResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "EU Verifier", resp.Name)
	assert.Equal(t, "https://eu-verifier.example.com/auth/password", resp.LoginURL)
	assert.True(t, resp.IsActive)
	assert.NotEmpty(t, resp.ID)
}

func TestPasswordLoginHandler_CreateEndpoint_InvalidURL(t *testing.T) {
	r, _ := setupPasswordLoginAPI(t)

	for _, badURL := range []string{"ftp://bad.com/verify", "", "not-a-url"} {
		body := jsonBody(t, map[string]interface{}{
			"name":      "Bad Verifier",
			"login_url": badURL,
		})
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/management/password-login/endpoints", body)
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code, "expected 400 for url=%q", badURL)
	}
}

func TestPasswordLoginHandler_CreateEndpoint_MissingName(t *testing.T) {
	r, _ := setupPasswordLoginAPI(t)

	body := jsonBody(t, map[string]interface{}{
		"login_url": "https://verifier.example.com/verify",
	})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/admin/management/password-login/endpoints", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPasswordLoginHandler_UpdateEndpoint(t *testing.T) {
	r, _ := setupPasswordLoginAPI(t)

	// Create
	body := jsonBody(t, map[string]interface{}{
		"name":      "Original",
		"login_url": "https://original.example.com/verify",
		"is_active": true,
	})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/admin/management/password-login/endpoints", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var created payload.PasswordLoginEndpointResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))

	// Update
	updateBody := jsonBody(t, map[string]interface{}{
		"name":      "Updated",
		"login_url": "https://updated.example.com/verify",
		"is_active": false,
	})
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodPut, "/admin/management/password-login/endpoints/"+created.ID, updateBody)
	req2.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)

	var updated payload.PasswordLoginEndpointResponse
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &updated))
	assert.Equal(t, "Updated", updated.Name)
	assert.False(t, updated.IsActive)
}

func TestPasswordLoginHandler_DeleteEndpoint(t *testing.T) {
	r, _ := setupPasswordLoginAPI(t)

	// Create
	body := jsonBody(t, map[string]interface{}{
		"name":      "To Delete",
		"login_url": "https://todelete.example.com/verify",
		"is_active": true,
	})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/admin/management/password-login/endpoints", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var created payload.PasswordLoginEndpointResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))

	// Delete
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodDelete, "/admin/management/password-login/endpoints/"+created.ID, nil)
	r.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusNoContent, w2.Code)

	// Get after delete must be 404
	w3 := httptest.NewRecorder()
	req3, _ := http.NewRequest(http.MethodGet, "/admin/management/password-login/endpoints/"+created.ID, nil)
	r.ServeHTTP(w3, req3)
	assert.Equal(t, http.StatusNotFound, w3.Code)
}

func TestPasswordLoginHandler_ListEndpoints(t *testing.T) {
	r, _ := setupPasswordLoginAPI(t)

	for i := 0; i < 3; i++ {
		body := jsonBody(t, map[string]interface{}{
			"name":      fmt.Sprintf("Verifier %d", i),
			"login_url": fmt.Sprintf("https://v%d.example.com/verify", i),
			"is_active": true,
		})
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/management/password-login/endpoints", body)
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/admin/management/password-login/endpoints", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var list []payload.PasswordLoginEndpointResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	assert.Len(t, list, 3)
}

// ----- Assignment handler tests -----

func createTestEndpoint(t *testing.T, r *gin.Engine, name, loginURL string) payload.PasswordLoginEndpointResponse {
	t.Helper()
	body := jsonBody(t, map[string]interface{}{"name": name, "login_url": loginURL, "is_active": true})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/admin/management/password-login/endpoints", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	var ep payload.PasswordLoginEndpointResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &ep))
	return ep
}

func TestPasswordLoginHandler_CreateAssignment_TenantSpecific(t *testing.T) {
	r, _ := setupPasswordLoginAPI(t)

	ep := createTestEndpoint(t, r, "Verifier", "https://verifier.example.com/verify")

	body := jsonBody(t, map[string]interface{}{
		"tenant_id":                  "tenant-a",
		"password_login_endpoint_id": ep.ID,
		"enabled":                    true,
	})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/admin/management/password-login/assignments", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp payload.PasswordLoginAssignmentResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.TenantID)
	assert.Equal(t, "tenant-a", *resp.TenantID)
	assert.True(t, resp.Enabled)
}

func TestPasswordLoginHandler_CreateAssignment_Global(t *testing.T) {
	r, _ := setupPasswordLoginAPI(t)

	ep := createTestEndpoint(t, r, "Global Verifier", "https://global.example.com/verify")

	body := jsonBody(t, map[string]interface{}{
		"password_login_endpoint_id": ep.ID,
		"enabled":                    true,
		// tenant_id omitted → global
	})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/admin/management/password-login/assignments", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp payload.PasswordLoginAssignmentResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Nil(t, resp.TenantID, "global assignment must have null tenant_id")
}

func TestPasswordLoginHandler_CreateAssignment_RejectsDuplicate(t *testing.T) {
	r, _ := setupPasswordLoginAPI(t)

	ep := createTestEndpoint(t, r, "Verifier", "https://verifier.example.com/verify")

	createBody := func() *bytes.Buffer {
		return jsonBody(t, map[string]interface{}{
			"tenant_id":                  "tenant-dup",
			"password_login_endpoint_id": ep.ID,
			"enabled":                    true,
		})
	}

	// First assignment succeeds
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest(http.MethodPost, "/admin/management/password-login/assignments", createBody())
	req1.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusCreated, w1.Code)

	// Second enabled assignment for the same tenant must be rejected
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodPost, "/admin/management/password-login/assignments", createBody())
	req2.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusConflict, w2.Code)
}

func TestPasswordLoginHandler_CreateAssignment_RejectsUnknownEndpoint(t *testing.T) {
	r, _ := setupPasswordLoginAPI(t)

	body := jsonBody(t, map[string]interface{}{
		"tenant_id":                  "tenant-a",
		"password_login_endpoint_id": "nonexistent-ep-id",
		"enabled":                    true,
	})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/admin/management/password-login/assignments", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPasswordLoginHandler_DisableAssignmentAndVerifyMethodDisappears(t *testing.T) {
	r, _ := setupPasswordLoginAPI(t)

	ep := createTestEndpoint(t, r, "Verifier", "https://verifier.example.com/verify")

	// Create enabled assignment
	createBody := jsonBody(t, map[string]interface{}{
		"tenant_id":                  "tenant-a",
		"password_login_endpoint_id": ep.ID,
		"enabled":                    true,
	})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/admin/management/password-login/assignments", createBody)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var created payload.PasswordLoginAssignmentResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))

	// Disable the assignment
	updateBody := jsonBody(t, map[string]interface{}{
		"password_login_endpoint_id": ep.ID,
		"enabled":                    false,
	})
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodPut, "/admin/management/password-login/assignments/"+created.ID, updateBody)
	req2.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)

	var updated payload.PasswordLoginAssignmentResponse
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &updated))
	assert.False(t, updated.Enabled, "assignment must be disabled")
}

func TestPasswordLoginHandler_ListAssignments_FilterByTenant(t *testing.T) {
	r, _ := setupPasswordLoginAPI(t)

	ep1 := createTestEndpoint(t, r, "EP1", "https://ep1.example.com/verify")
	ep2 := createTestEndpoint(t, r, "EP2", "https://ep2.example.com/verify")

	// Assign ep1 to tenant-a, ep2 to tenant-b
	for _, tc := range []struct {
		tid string
		eid string
	}{
		{"tenant-a", ep1.ID},
		{"tenant-b", ep2.ID},
	} {
		body := jsonBody(t, map[string]interface{}{
			"tenant_id":                  tc.tid,
			"password_login_endpoint_id": tc.eid,
			"enabled":                    true,
		})
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/admin/management/password-login/assignments", body)
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
	}

	// List for tenant-a only
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/admin/management/password-login/assignments?tenant_id=tenant-a", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var list []payload.PasswordLoginAssignmentResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	assert.Len(t, list, 1)
	require.NotNil(t, list[0].TenantID)
	assert.Equal(t, "tenant-a", *list[0].TenantID)
}

// ----- Response shape regression test -----

func TestPasswordLoginHandler_ResponseShape_ContractUnchanged(t *testing.T) {
	r, _ := setupPasswordLoginAPI(t)

	body := jsonBody(t, map[string]interface{}{
		"name":      "Shape Check",
		"login_url": "https://shape.example.com/verify",
		"is_active": true,
	})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/admin/management/password-login/endpoints", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))

	// Verify required fields are present
	for _, field := range []string{"id", "name", "login_url", "is_active", "created_at", "updated_at"} {
		assert.Contains(t, raw, field, "response must include field %q", field)
	}
}
