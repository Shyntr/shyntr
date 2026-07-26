package handlers_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Shyntr/shyntr/internal/adapters/persistence/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestManagement_CreateClient_PersistsPassthroughAndExclude is a handler-level
// regression test for the bug where CreateClient built the domain model inline and
// dropped AttributePassthrough + AttributeExclude (they were never persisted). It
// drives the real POST handler with the two fields set, then reads the persisted
// model back from the store and asserts both survived.
func TestManagement_CreateClient_PersistsPassthroughAndExclude(t *testing.T) {
	r, db := setupManagementAPI(t)
	defer db.Exec("DELETE FROM o_auth2_clients")

	body := []byte(`{
		"client_id": "client-attr-pt",
		"tenant_id": "tenant-a",
		"name": "Attr Policy Client",
		"public": true,
		"token_endpoint_auth_method": "none",
		"redirect_uris": ["https://app.example.com/callback"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"scopes": ["openid", "profile"],
		"attribute_passthrough": true,
		"attribute_exclude": ["x"]
	}`)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/admin/management/clients", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "create must succeed: %s", w.Body.String())

	// Read the persisted model straight from the store.
	fetched, err := repository.NewOAuth2ClientRepository(db).
		GetByTenantAndID(context.Background(), "tenant-a", "client-attr-pt")
	require.NoError(t, err)

	assert.True(t, fetched.AttributePassthrough,
		"attribute_passthrough must be persisted by the create handler")
	assert.Equal(t, []string{"x"}, fetched.AttributeExclude,
		"attribute_exclude must be persisted by the create handler")
}
