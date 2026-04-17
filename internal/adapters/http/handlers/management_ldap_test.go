package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/audit"
	"github.com/Shyntr/shyntr/internal/adapters/http/handlers"
	"github.com/Shyntr/shyntr/internal/adapters/http/middleware"
	"github.com/Shyntr/shyntr/internal/adapters/iam"
	"github.com/Shyntr/shyntr/internal/adapters/persistence"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/repository"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/application/security"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	utils2 "github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type mgmtLDAPSessionStub struct{}

func (s *mgmtLDAPSessionStub) Authenticate(context.Context, string, string) error { return nil }
func (s *mgmtLDAPSessionStub) Search(context.Context, string, []string) ([]model.LDAPEntry, error) {
	return nil, nil
}
func (s *mgmtLDAPSessionStub) Close() error { return nil }

type mgmtLDAPDialerStub struct{}

func (d *mgmtLDAPDialerStub) Dial(context.Context, *model.LDAPConnection) (port.LDAPSession, error) {
	return &mgmtLDAPSessionStub{}, nil
}

func setupManagementLDAPAPI(t *testing.T) (*gin.Engine, *gorm.DB) {
	t.Helper()
	logger.InitLogger("info")
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, persistence.MigrateDB(db))

	require.NoError(t, db.Create(&models.TenantGORM{ID: "default", Name: "default"}).Error)
	require.NoError(t, db.Create(&models.TenantGORM{ID: "tenant-a", Name: "Tenant A"}).Error)
	require.NoError(t, db.Create(&models.TenantGORM{ID: "tenant-b", Name: "Tenant B"}).Error)

	cfg := &config.Config{
		AppSecret:     "12345678901234567890123456789012",
		BaseIssuerURL: "http://localhost:7496",
	}
	keyRepository := repository.NewCryptoKeyRepository(db)
	keyMgr := utils2.NewKeyManager(keyRepository, cfg)
	keyMgr.GetActivePrivateKey(context.Background(), "sig")

	fositeConfig := &fosite.Config{
		AccessTokenLifespan:        time.Hour,
		AuthorizeCodeLifespan:      10 * time.Minute,
		IDTokenLifespan:            time.Hour,
		RefreshTokenLifespan:       30 * 24 * time.Hour,
		GlobalSecret:               []byte(cfg.AppSecret),
		IDTokenIssuer:              cfg.BaseIssuerURL,
		SendDebugMessagesToClients: true,
	}

	policyRepository := repository.NewOutboundPolicyRepository(db)
	outboundGuard := security.NewOutboundGuard(policyRepository, cfg.SkipTLSVerify)
	requestRepository := repository.NewAuthRequestRepository(db)
	tenantRepository := repository.NewTenantRepository(db)
	clientRepository := repository.NewOAuth2ClientRepository(db)
	samlClientRepository := repository.NewSAMLClientRepository(db)
	sessionRepository := repository.NewOAuth2SessionRepository(db)
	connectionRepository := repository.NewOIDCConnectionRepository(db)
	samlConnectionRepository := repository.NewSAMLConnectionRepository(db)
	ldapRepository := repository.NewLDAPConnectionRepository(db, []byte(cfg.AppSecret))
	scopeRepository := repository.NewScopeRepository(db)
	auditLogger := audit.NewAuditLogger(db)
	auditLogRepository := repository.NewAuditLogRepository(db)
	auditUseCase := usecase.NewAuditUseCase(auditLogRepository)

	fositeSecretHasher := iam.NewFositeSecretHasher(fositeConfig)
	auth2ClientUseCase := usecase.NewOAuth2ClientUseCase(clientRepository, connectionRepository, tenantRepository, auditLogger, fositeSecretHasher, keyMgr, outboundGuard, cfg)
	authUseCase := usecase.NewAuthUseCase(requestRepository, auditLogger)
	tenantUseCase := usecase.NewTenantUseCase(tenantRepository, auditLogger, scopeRepository)
	clientUseCase := usecase.NewSAMLClientUseCase(samlClientRepository, tenantRepository, auditLogger, outboundGuard)
	connectionUseCase := usecase.NewOIDCConnectionUseCase(connectionRepository, auditLogger, nil, outboundGuard)
	samlConnectionUseCase := usecase.NewSAMLConnectionUseCase(samlConnectionRepository, auditLogger, nil, outboundGuard)
	sessionUseCase := usecase.NewOAuth2SessionUseCase(sessionRepository, auditLogger)
	scopeUseCase := usecase.NewScopeUseCase(scopeRepository, auditLogger)
	ldapUseCase := usecase.NewLDAPConnectionUseCase(ldapRepository, &mgmtLDAPDialerStub{}, auditLogger, scopeUseCase, outboundGuard)

	handler := handlers.NewManagementHandler(fositeConfig, auth2ClientUseCase, clientUseCase, samlConnectionUseCase, authUseCase, sessionUseCase, connectionUseCase, ldapUseCase, tenantUseCase, auditUseCase, outboundGuard)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.ErrorHandlerMiddleware())
	r.GET("/admin/management/ldap-connections", handler.ListLDAPConnections)
	r.GET("/admin/management/ldap-connections/:tenant_id/:id", handler.GetLDAPConnection)
	r.POST("/admin/management/ldap-connections", handler.CreateLDAPConnection)
	r.PUT("/admin/management/ldap-connections/:tenant_id/:id", handler.UpdateLDAPConnection)
	r.DELETE("/admin/management/ldap-connections/:tenant_id/:id", handler.DeleteLDAPConnection)
	r.POST("/admin/management/ldap-connections/:tenant_id/:id/test", handler.TestLDAPConnection)
	return r, db
}

func TestManagementLDAPContract_CRUDAndIsolation(t *testing.T) {
	r, db := setupManagementLDAPAPI(t)

	createPayload := func(id, tenantID, name, bindPassword string) []byte {
		body, err := json.Marshal(map[string]interface{}{
			"id":                 id,
			"tenant_id":          tenantID,
			"name":               name,
			"server_url":         "ldap://192.0.2.10:389",
			"bind_dn":            "cn=svc,dc=example,dc=com",
			"bind_password":      bindPassword,
			"base_dn":            "dc=example,dc=com",
			"user_search_filter": "(uid={0})",
		})
		require.NoError(t, err)
		return body
	}

	t.Run("create and global list remains cross tenant", func(t *testing.T) {
		for _, tc := range []struct {
			id, tenantID, name string
		}{
			{"ldap-a", "tenant-a", "Tenant A LDAP"},
			{"ldap-b", "tenant-b", "Tenant B LDAP"},
		} {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/admin/management/ldap-connections", bytes.NewReader(createPayload(tc.id, tc.tenantID, tc.name, "secret")))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)
			require.Equal(t, http.StatusCreated, w.Code)
		}

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/admin/management/ldap-connections", nil)
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var conns []map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &conns))
		require.Len(t, conns, 2)
		tenantSet := map[string]bool{}
		for _, c := range conns {
			tenantSet[c["tenant_id"].(string)] = true
		}
		assert.True(t, tenantSet["tenant-a"])
		assert.True(t, tenantSet["tenant-b"])
	})

	t.Run("get by tenant and id", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/admin/management/ldap-connections/tenant-a/ldap-a", nil)
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `"id":"ldap-a"`)
		assert.Contains(t, w.Body.String(), `"tenant_id":"tenant-a"`)
	})

	t.Run("password preservation with empty string", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/admin/management/ldap-connections/tenant-a/ldap-a", bytes.NewReader(createPayload("ignored", "ignored", "Tenant A LDAP Updated", "")))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		repo := repository.NewLDAPConnectionRepository(db, []byte("12345678901234567890123456789012"))
		conn, err := repo.GetByTenantAndID(context.Background(), "tenant-a", "ldap-a")
		require.NoError(t, err)
		assert.Equal(t, "secret", conn.BindPassword)
	})

	t.Run("password preservation with sentinel", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/admin/management/ldap-connections/tenant-a/ldap-a", bytes.NewReader(createPayload("ignored", "ignored", "Tenant A LDAP Updated Again", "*****")))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		repo := repository.NewLDAPConnectionRepository(db, []byte("12345678901234567890123456789012"))
		conn, err := repo.GetByTenantAndID(context.Background(), "tenant-a", "ldap-a")
		require.NoError(t, err)
		assert.Equal(t, "secret", conn.BindPassword)
	})

	t.Run("wrong tenant item operations behave as not found", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			method string
			path   string
			body   []byte
		}{
			{"get", "GET", "/admin/management/ldap-connections/tenant-b/ldap-a", nil},
			{"update", "PUT", "/admin/management/ldap-connections/tenant-b/ldap-a", createPayload("ignored", "ignored", "Wrong Tenant", "*****")},
			{"delete", "DELETE", "/admin/management/ldap-connections/tenant-b/ldap-a", nil},
			{"test", "POST", "/admin/management/ldap-connections/tenant-b/ldap-a/test", nil},
		} {
			t.Run(tc.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				req, _ := http.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
				if tc.body != nil {
					req.Header.Set("Content-Type", "application/json")
				}
				r.ServeHTTP(w, req)
				assert.Equal(t, http.StatusNotFound, w.Code)
			})
		}
	})

	t.Run("delete correct tenant", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/admin/management/ldap-connections/tenant-a/ldap-a", nil)
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusNoContent, w.Code)
	})
}
