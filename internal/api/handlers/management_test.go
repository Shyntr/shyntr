package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/nevzatcirak/shyntr/internal/api/handlers"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func setupManagementAPI(t *testing.T) (*gin.Engine, *gorm.DB) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}
	db.AutoMigrate(&models.Tenant{}, &models.OAuth2Client{})

	db.Create(&models.Tenant{ID: "default", Name: "default"})
	db.Create(&models.Tenant{ID: "tenant-a", Name: "Tenant A"})
	db.Create(&models.Tenant{ID: "tenant-b", Name: "Tenant B"})

	db.Create(&models.OAuth2Client{ID: "client-a1", TenantID: "tenant-a", Name: "A1"})
	db.Create(&models.OAuth2Client{ID: "client-b1", TenantID: "tenant-b", Name: "B1"})

	handler := handlers.NewManagementHandler(db)

	gin.SetMode(gin.TestMode)
	r := gin.New()

	r.DELETE("/tenants/:id", handler.DeleteTenant)
	r.GET("/clients/tenant/:tenant_id", handler.ListClientsByTenant)
	r.POST("/clients", handler.CreateClient)

	return r, db
}

func TestManagementAPI_Security(t *testing.T) {
	r, db := setupManagementAPI(t)

	defer db.Exec("DELETE FROM oauth2_clients")
	defer db.Exec("DELETE FROM tenants")

	t.Run("Prevent Deletion of Default Tenant", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/tenants/default", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "cannot delete default tenant")
	})

	t.Run("Prevent Cross-Tenant Data Leakage (Client Listing)", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/clients/tenant/tenant-a", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var clients []models.OAuth2Client
		err := json.Unmarshal(w.Body.Bytes(), &clients)
		assert.NoError(t, err)

		assert.Len(t, clients, 1)
		assert.Equal(t, "client-a1", clients[0].ID)
		assert.Equal(t, "tenant-a", clients[0].TenantID)
	})

	t.Run("Enforce Tenant Binding on Resource Creation", func(t *testing.T) {
		payload := []byte(`{"id": "hacker-client", "tenant_id": "non-existent-tenant", "name": "Evil Client"}`)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/clients", bytes.NewBuffer(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "tenant_not_found")
	})
}
