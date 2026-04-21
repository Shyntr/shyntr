package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/audit"
	"github.com/Shyntr/shyntr/internal/adapters/http/handlers"
	"github.com/Shyntr/shyntr/internal/adapters/http/middleware"
	"github.com/Shyntr/shyntr/internal/adapters/http/payload"
	"github.com/Shyntr/shyntr/internal/adapters/iam"
	"github.com/Shyntr/shyntr/internal/adapters/persistence"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/models"
	"github.com/Shyntr/shyntr/internal/adapters/persistence/repository"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	utils2 "github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const samlManagementMetadataXML = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>MIIDFAKECERT</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/slo"/></IDPSSODescriptor></EntityDescriptor>`

type allowAllOutboundGuard struct{}

func (g *allowAllOutboundGuard) ValidateURL(_ context.Context, _ string, _ model.OutboundTargetType, rawURL string) (*url.URL, *model.OutboundPolicy, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	return parsed, &model.OutboundPolicy{}, nil
}

func (g *allowAllOutboundGuard) NewHTTPClient(_ context.Context, _ string, _ model.OutboundTargetType, _ *model.OutboundPolicy) *http.Client {
	return &http.Client{}
}

func setupManagementConnectionsAPI(t *testing.T) (*gin.Engine, *gorm.DB) {
	t.Helper()
	logger.InitLogger("info")
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString())), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, persistence.MigrateDB(db))

	require.NoError(t, db.Create(&models.TenantGORM{ID: "default", Name: "default"}).Error)
	require.NoError(t, db.Create(&models.TenantGORM{ID: "tenant-a", Name: "Tenant A"}).Error)
	require.NoError(t, db.Create(&models.TenantGORM{ID: "tenant-b", Name: "Tenant B"}).Error)
	require.NoError(t, db.Create(&models.OAuth2ClientGORM{
		ID:                      "client-a1",
		TenantID:                "tenant-a",
		Name:                    "A1",
		Secret:                  "hashed-secret",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ResponseModes:           []string{"query"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
		EnforcePKCE:             true,
		SubjectType:             "public",
	}).Error)

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

	var outboundGuard port.OutboundGuard = &allowAllOutboundGuard{}
	requestRepository := repository.NewAuthRequestRepository(db)
	tenantRepository := repository.NewTenantRepository(db)
	clientRepository := repository.NewOAuth2ClientRepository(db)
	samlClientRepository := repository.NewSAMLClientRepository(db)
	sessionRepository := repository.NewOAuth2SessionRepository(db)
	connectionRepository := repository.NewOIDCConnectionRepository(db)
	samlConnectionRepository := repository.NewSAMLConnectionRepository(db)
	scopeRepository := repository.NewScopeRepository(db)
	auditLogger := audit.NewAuditLogger(db)
	auditLogRepository := repository.NewAuditLogRepository(db)
	auditUseCase := usecase.NewAuditUseCase(auditLogRepository)
	healthRepository := repository.NewHealthRepository(db)
	healthUseCase := usecase.NewHealthUseCase(healthRepository, keyMgr)

	fositeSecretHasher := iam.NewFositeSecretHasher(fositeConfig)
	auth2ClientUseCase := usecase.NewOAuth2ClientUseCase(clientRepository, connectionRepository, tenantRepository, auditLogger, fositeSecretHasher, keyMgr, outboundGuard, cfg)
	authUseCase := usecase.NewAuthUseCase(requestRepository, auditLogger)
	tenantUseCase := usecase.NewTenantUseCase(tenantRepository, auditLogger, scopeRepository)
	clientUseCase := usecase.NewSAMLClientUseCase(samlClientRepository, tenantRepository, auditLogger, outboundGuard)
	connectionUseCase := usecase.NewOIDCConnectionUseCase(connectionRepository, auditLogger, nil, outboundGuard)
	samlConnectionUseCase := usecase.NewSAMLConnectionUseCase(samlConnectionRepository, auditLogger, nil, outboundGuard)
	sessionUseCase := usecase.NewOAuth2SessionUseCase(sessionRepository, auditLogger)

	handler := handlers.NewManagementHandler(fositeConfig, auth2ClientUseCase, clientUseCase, samlConnectionUseCase, authUseCase, sessionUseCase, connectionUseCase, nil, tenantUseCase, auditUseCase, healthUseCase, outboundGuard, nil)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.ErrorHandlerMiddleware())

	r.POST("/admin/management/oidc-connections", handler.CreateOIDCConnection)
	r.GET("/admin/management/oidc-connections", handler.ListOIDCConnections)
	r.GET("/admin/management/tenants/:id/oidc-connections", handler.ListOIDCConnectionsByTenant)
	r.GET("/admin/management/oidc-connections/:tenant_id/:id", handler.GetOIDCConnection)
	r.PUT("/admin/management/oidc-connections/:id", handler.UpdateOIDCConnection)

	r.POST("/admin/management/saml-connections", handler.CreateSAMLConnection)
	r.GET("/admin/management/saml-connections", handler.ListSAMLConnections)
	r.GET("/admin/management/tenants/:id/saml-connections", handler.ListSAMLConnectionsByTenant)
	r.GET("/admin/management/saml-connections/:tenant_id/:id", handler.GetSAMLConnection)
	r.PUT("/admin/management/saml-connections/:id", handler.UpdateSAMLConnection)

	r.PUT("/admin/management/clients/:id", handler.UpdateClient)

	return r, db
}

func oidcConnectionPayload(id, tenantID, secret string) []byte {
	body, _ := json.Marshal(map[string]interface{}{
		"id":                     id,
		"tenant_id":              tenantID,
		"name":                   "Tenant OIDC Connection",
		"issuer_url":             "https://127.0.0.1:9443",
		"client_id":              "oidc-client",
		"client_secret":          secret,
		"scopes":                 []string{"openid", "profile", "email"},
		"authorization_endpoint": "https://127.0.0.1:9443/auth",
		"token_endpoint":         "https://127.0.0.1:9443/token",
		"user_info_endpoint":     "https://127.0.0.1:9443/userinfo",
		"jwks_uri":               "https://127.0.0.1:9443/jwks",
		"end_session_endpoint":   "https://127.0.0.1:9443/logout",
	})
	return body
}

func samlConnectionPayload(id, tenantID, privateKey string) []byte {
	body, _ := json.Marshal(map[string]interface{}{
		"id":               id,
		"tenant_id":        tenantID,
		"name":             "Tenant SAML Connection",
		"idp_metadata_xml": samlManagementMetadataXML,
		"sp_private_key":   privateKey,
	})
	return body
}

func oidcClientUpdatePayload(id, tenantID string) []byte {
	body, _ := json.Marshal(map[string]interface{}{
		"client_id":                  id,
		"tenant_id":                  tenantID,
		"name":                       "Updated Client",
		"redirect_uris":              []string{"https://app.example.com/callback"},
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"response_modes":             []string{"query"},
		"scopes":                     []string{"openid"},
		"token_endpoint_auth_method": "client_secret_basic",
		"enforce_pkce":               true,
		"subject_type":               "public",
	})
	return body
}

func TestManagementConnections_RedactsSensitiveFields(t *testing.T) {
	r, _ := setupManagementConnectionsAPI(t)

	t.Run("oidc responses are redacted", func(t *testing.T) {
		wCreate := httptest.NewRecorder()
		reqCreate, _ := http.NewRequest("POST", "/admin/management/oidc-connections", bytes.NewReader(oidcConnectionPayload("", "tenant-a", "super-secret-oidc")))
		reqCreate.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(wCreate, reqCreate)
		require.Equal(t, http.StatusCreated, wCreate.Code)

		var created payload.OIDCConnectionResponse
		require.NoError(t, json.Unmarshal(wCreate.Body.Bytes(), &created))
		assert.Equal(t, "*****", created.ClientSecret)
		assert.NotContains(t, wCreate.Body.String(), "super-secret-oidc")

		wList := httptest.NewRecorder()
		reqList, _ := http.NewRequest("GET", "/admin/management/oidc-connections", nil)
		r.ServeHTTP(wList, reqList)
		require.Equal(t, http.StatusOK, wList.Code)

		var listed []payload.OIDCConnectionResponse
		require.NoError(t, json.Unmarshal(wList.Body.Bytes(), &listed))
		require.Len(t, listed, 1)
		assert.Equal(t, "*****", listed[0].ClientSecret)
		assert.NotContains(t, wList.Body.String(), "super-secret-oidc")

		wTenantList := httptest.NewRecorder()
		reqTenantList, _ := http.NewRequest("GET", "/admin/management/tenants/tenant-a/oidc-connections", nil)
		r.ServeHTTP(wTenantList, reqTenantList)
		require.Equal(t, http.StatusOK, wTenantList.Code)

		var tenantListed []payload.OIDCConnectionResponse
		require.NoError(t, json.Unmarshal(wTenantList.Body.Bytes(), &tenantListed))
		require.Len(t, tenantListed, 1)
		assert.Equal(t, "*****", tenantListed[0].ClientSecret)
		assert.NotContains(t, wTenantList.Body.String(), "super-secret-oidc")

		wGet := httptest.NewRecorder()
		reqGet, _ := http.NewRequest("GET", "/admin/management/oidc-connections/tenant-a/"+created.ID, nil)
		r.ServeHTTP(wGet, reqGet)
		require.Equal(t, http.StatusOK, wGet.Code)

		var fetched payload.OIDCConnectionResponse
		require.NoError(t, json.Unmarshal(wGet.Body.Bytes(), &fetched))
		assert.Equal(t, "*****", fetched.ClientSecret)
		assert.NotContains(t, wGet.Body.String(), "super-secret-oidc")
	})

	t.Run("saml responses are redacted", func(t *testing.T) {
		wCreate := httptest.NewRecorder()
		reqCreate, _ := http.NewRequest("POST", "/admin/management/saml-connections", bytes.NewReader(samlConnectionPayload("", "tenant-a", "super-secret-private-key")))
		reqCreate.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(wCreate, reqCreate)
		require.Equal(t, http.StatusCreated, wCreate.Code)

		var created payload.SAMLConnectionResponse
		require.NoError(t, json.Unmarshal(wCreate.Body.Bytes(), &created))
		assert.Equal(t, "*****", created.SPPrivateKey)
		assert.NotContains(t, wCreate.Body.String(), "super-secret-private-key")

		wList := httptest.NewRecorder()
		reqList, _ := http.NewRequest("GET", "/admin/management/saml-connections", nil)
		r.ServeHTTP(wList, reqList)
		require.Equal(t, http.StatusOK, wList.Code)

		var listed []payload.SAMLConnectionResponse
		require.NoError(t, json.Unmarshal(wList.Body.Bytes(), &listed))
		require.Len(t, listed, 1)
		assert.Equal(t, "*****", listed[0].SPPrivateKey)
		assert.NotContains(t, wList.Body.String(), "super-secret-private-key")

		wTenantList := httptest.NewRecorder()
		reqTenantList, _ := http.NewRequest("GET", "/admin/management/tenants/tenant-a/saml-connections", nil)
		r.ServeHTTP(wTenantList, reqTenantList)
		require.Equal(t, http.StatusOK, wTenantList.Code)

		var tenantListed []payload.SAMLConnectionResponse
		require.NoError(t, json.Unmarshal(wTenantList.Body.Bytes(), &tenantListed))
		require.Len(t, tenantListed, 1)
		assert.Equal(t, "*****", tenantListed[0].SPPrivateKey)
		assert.NotContains(t, wTenantList.Body.String(), "super-secret-private-key")

		wGet := httptest.NewRecorder()
		reqGet, _ := http.NewRequest("GET", "/admin/management/saml-connections/tenant-a/"+created.ID, nil)
		r.ServeHTTP(wGet, reqGet)
		require.Equal(t, http.StatusOK, wGet.Code)

		var fetched payload.SAMLConnectionResponse
		require.NoError(t, json.Unmarshal(wGet.Body.Bytes(), &fetched))
		assert.Equal(t, "*****", fetched.SPPrivateKey)
		assert.NotContains(t, wGet.Body.String(), "super-secret-private-key")
	})
}

func TestManagementUpdates_RejectRetargetingAndFailClosed(t *testing.T) {
	r, _ := setupManagementConnectionsAPI(t)

	wCreateOIDC := httptest.NewRecorder()
	reqCreateOIDC, _ := http.NewRequest("POST", "/admin/management/oidc-connections", bytes.NewReader(oidcConnectionPayload("oidc-conn-a", "tenant-a", "super-secret-oidc")))
	reqCreateOIDC.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(wCreateOIDC, reqCreateOIDC)
	require.Equal(t, http.StatusCreated, wCreateOIDC.Code)
	var createdOIDC payload.OIDCConnectionResponse
	require.NoError(t, json.Unmarshal(wCreateOIDC.Body.Bytes(), &createdOIDC))

	wCreateSAML := httptest.NewRecorder()
	reqCreateSAML, _ := http.NewRequest("POST", "/admin/management/saml-connections", bytes.NewReader(samlConnectionPayload("saml-conn-a", "tenant-a", "super-secret-private-key")))
	reqCreateSAML.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(wCreateSAML, reqCreateSAML)
	require.Equal(t, http.StatusCreated, wCreateSAML.Code)
	var createdSAML payload.SAMLConnectionResponse
	require.NoError(t, json.Unmarshal(wCreateSAML.Body.Bytes(), &createdSAML))

	t.Run("oidc connection update rejects path and body id mismatch", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/admin/management/oidc-connections/"+createdOIDC.ID, bytes.NewReader(oidcConnectionPayload("other-oidc-id", "tenant-a", "rotated-secret")))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), `"code":"path_body_mismatch"`)
	})

	t.Run("saml connection update rejects path and body id mismatch", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/admin/management/saml-connections/"+createdSAML.ID, bytes.NewReader(samlConnectionPayload("other-saml-id", "tenant-a", "rotated-private-key")))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), `"code":"path_body_mismatch"`)
	})

	t.Run("client update rejects path and body id mismatch", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/admin/management/clients/client-a1", bytes.NewReader(oidcClientUpdatePayload("client-b1", "tenant-a")))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), `"code":"path_body_mismatch"`)
	})

	t.Run("oidc connection update with wrong tenant fails closed", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/admin/management/oidc-connections/"+createdOIDC.ID, bytes.NewReader(oidcConnectionPayload(createdOIDC.ID, "tenant-b", "rotated-secret")))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), `"code":"resource_not_found"`)
	})
}

func TestManagementConnections_UpdatePreservesSensitiveValues(t *testing.T) {
	r, db := setupManagementConnectionsAPI(t)

	oidcRepo := repository.NewOIDCConnectionRepository(db)
	samlRepo := repository.NewSAMLConnectionRepository(db)

	wCreateOIDC := httptest.NewRecorder()
	reqCreateOIDC, _ := http.NewRequest("POST", "/admin/management/oidc-connections", bytes.NewReader(oidcConnectionPayload("oidc-preserve", "tenant-a", "initial-oidc-secret")))
	reqCreateOIDC.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(wCreateOIDC, reqCreateOIDC)
	require.Equal(t, http.StatusCreated, wCreateOIDC.Code)

	wCreateSAML := httptest.NewRecorder()
	reqCreateSAML, _ := http.NewRequest("POST", "/admin/management/saml-connections", bytes.NewReader(samlConnectionPayload("saml-preserve", "tenant-a", "initial-saml-key")))
	reqCreateSAML.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(wCreateSAML, reqCreateSAML)
	require.Equal(t, http.StatusCreated, wCreateSAML.Code)
	var createdSAML payload.SAMLConnectionResponse
	require.NoError(t, json.Unmarshal(wCreateSAML.Body.Bytes(), &createdSAML))

	oidcUpdatePayload := func(secret string) []byte {
		body, _ := json.Marshal(map[string]interface{}{
			"id":                     "oidc-preserve",
			"tenant_id":              "tenant-a",
			"name":                   "Updated Tenant OIDC Connection",
			"issuer_url":             "https://127.0.0.1:9443",
			"client_id":              "oidc-client",
			"client_secret":          secret,
			"scopes":                 []string{"openid", "profile", "email"},
			"authorization_endpoint": "https://127.0.0.1:9443/auth",
			"token_endpoint":         "https://127.0.0.1:9443/token",
			"user_info_endpoint":     "https://127.0.0.1:9443/userinfo",
			"jwks_uri":               "https://127.0.0.1:9443/jwks",
			"end_session_endpoint":   "https://127.0.0.1:9443/logout",
		})
		return body
	}

	samlUpdatePayload := func(key string) []byte {
		body, _ := json.Marshal(map[string]interface{}{
			"id":               createdSAML.ID,
			"tenant_id":        "tenant-a",
			"name":             "Updated Tenant SAML Connection",
			"idp_metadata_xml": samlManagementMetadataXML,
			"sp_private_key":   key,
		})
		return body
	}

	t.Run("oidc preserves secret when blank", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/admin/management/oidc-connections/oidc-preserve", bytes.NewReader(oidcUpdatePayload("")))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		conn, err := oidcRepo.GetByTenantAndID(context.Background(), "tenant-a", "oidc-preserve")
		require.NoError(t, err)
		assert.Equal(t, "initial-oidc-secret", conn.ClientSecret)
	})

	t.Run("oidc preserves secret when masked", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/admin/management/oidc-connections/oidc-preserve", bytes.NewReader(oidcUpdatePayload("*****")))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		conn, err := oidcRepo.GetByTenantAndID(context.Background(), "tenant-a", "oidc-preserve")
		require.NoError(t, err)
		assert.Equal(t, "initial-oidc-secret", conn.ClientSecret)
	})

	t.Run("oidc replaces secret when new value provided", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/admin/management/oidc-connections/oidc-preserve", bytes.NewReader(oidcUpdatePayload("rotated-oidc-secret")))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		conn, err := oidcRepo.GetByTenantAndID(context.Background(), "tenant-a", "oidc-preserve")
		require.NoError(t, err)
		assert.Equal(t, "rotated-oidc-secret", conn.ClientSecret)
	})

	t.Run("saml preserves private key when blank", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/admin/management/saml-connections/"+createdSAML.ID, bytes.NewReader(samlUpdatePayload("")))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		conn, err := samlRepo.GetByTenantAndID(context.Background(), "tenant-a", createdSAML.ID)
		require.NoError(t, err)
		assert.Equal(t, "initial-saml-key", conn.SPPrivateKey)
	})

	t.Run("saml preserves private key when masked", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/admin/management/saml-connections/"+createdSAML.ID, bytes.NewReader(samlUpdatePayload("*****")))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		conn, err := samlRepo.GetByTenantAndID(context.Background(), "tenant-a", createdSAML.ID)
		require.NoError(t, err)
		assert.Equal(t, "initial-saml-key", conn.SPPrivateKey)
	})

	t.Run("saml replaces private key when new value provided", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/admin/management/saml-connections/"+createdSAML.ID, bytes.NewReader(samlUpdatePayload("rotated-saml-key")))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		conn, err := samlRepo.GetByTenantAndID(context.Background(), "tenant-a", createdSAML.ID)
		require.NoError(t, err)
		assert.Equal(t, "rotated-saml-key", conn.SPPrivateKey)
	})
}
