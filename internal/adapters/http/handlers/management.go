package handlers

import (
	"net/http"

	"github.com/Shyntr/shyntr/internal/adapters/http/payload"
	"github.com/Shyntr/shyntr/internal/application/port"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	shyntrsaml "github.com/Shyntr/shyntr/internal/application/utils"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"go.uber.org/zap"
)

type ManagementHandler struct {
	FositeConfig     *fosite.Config
	OAuth2ClientUse  usecase.OAuth2ClientUseCase
	SAMLClientUse    usecase.SAMLClientUseCase
	SAMLConnUse      usecase.SAMLConnectionUseCase
	OIDCConnUse      usecase.OIDCConnectionUseCase
	LDAPConnUse      usecase.LDAPConnectionUseCase
	OAuth2SessionUse usecase.OAuth2SessionUseCase
	AuthReq          usecase.AuthUseCase
	TenantUse        usecase.TenantUseCase
	OutboundGuard    port.OutboundGuard
}

func NewManagementHandler(fositeCfg *fosite.Config, OAuth2ClientUse usecase.OAuth2ClientUseCase, SAMLClientUse usecase.SAMLClientUseCase,
	SAMLConnUse usecase.SAMLConnectionUseCase, AuthReq usecase.AuthUseCase,
	OAuth2SessionUse usecase.OAuth2SessionUseCase, OIDCConnUse usecase.OIDCConnectionUseCase,
	LDAPConnUse usecase.LDAPConnectionUseCase,
	TenantUse usecase.TenantUseCase, OutboundGuard port.OutboundGuard) *ManagementHandler {
	return &ManagementHandler{FositeConfig: fositeCfg, OAuth2ClientUse: OAuth2ClientUse, AuthReq: AuthReq,
		OAuth2SessionUse: OAuth2SessionUse, TenantUse: TenantUse, OIDCConnUse: OIDCConnUse,
		SAMLConnUse: SAMLConnUse, SAMLClientUse: SAMLClientUse, LDAPConnUse: LDAPConnUse, OutboundGuard: OutboundGuard}
}

func (h *ManagementHandler) resolveTenantID(c *gin.Context, inputID string) (string, bool) {
	if inputID == "" {
		c.Error(payload.NewRequiredQueryParamError("tenant_id"))
		return "", false
	}

	tenant, err := h.TenantUse.GetTenant(c.Request.Context(), inputID)
	if err == nil {
		return tenant.ID, true
	}
	tenant, err = h.TenantUse.GetTenantByName(c.Request.Context(), inputID)
	if err == nil {
		return tenant.ID, true
	}

	c.Error(payload.NewNotFoundAppError("Tenant", nil))
	return "", false
}

// GetDashboardStats godoc
// @Summary Get Dashboard Statistics
// @Description Retrieves global or tenant-specific usage statistics and active connection counts.
// @Tags Dashboard
// @Produce json
// @Security BearerAuth
// @Param tenant_id query string false "Tenant ID (for filtering)"
// @Success 200 {object} map[string]interface{} "Returns system statistics and recent activity"
// @Router /admin/management/dashboard/stats [get]
func (h *ManagementHandler) GetDashboardStats(c *gin.Context) {
	tenantID := c.Query("tenant_id")
	ctx := c.Request.Context()

	var stats struct {
		TotalOIDCClients     int64                    `json:"total_oidc_clients"`
		TotalSAMLClients     int64                    `json:"total_saml_clients"`
		TotalSAMLConnections int64                    `json:"total_saml_connections"`
		TotalOIDCConnections int64                    `json:"total_oidc_connections"`
		TotalTenants         int64                    `json:"total_tenants"`
		PublicClients        int64                    `json:"public_clients"`
		ConfidentialClients  int64                    `json:"confidential_clients"`
		RecentActivity       []map[string]interface{} `json:"recent_activity"`
	}

	stats.TotalOIDCClients, _ = h.OAuth2ClientUse.GetClientCount(ctx, tenantID)
	stats.PublicClients, _ = h.OAuth2ClientUse.GetPublicClientCount(ctx, tenantID)
	stats.ConfidentialClients, _ = h.OAuth2ClientUse.GetConfidentialClientCount(ctx, tenantID)
	stats.TotalSAMLClients, _ = h.SAMLClientUse.GetClientCount(ctx, tenantID)
	stats.TotalSAMLConnections, _ = h.SAMLConnUse.GetConnectionCount(ctx, tenantID)
	stats.TotalOIDCConnections, _ = h.OIDCConnUse.GetConnectionCount(ctx, tenantID)
	stats.TotalTenants, _ = h.TenantUse.GetCount(ctx)

	recentLogins, _ := h.AuthReq.GetRecentLogins(ctx, tenantID, 10)

	stats.RecentActivity = make([]map[string]interface{}, 0)
	for _, l := range recentLogins {
		status := "Pending"
		if l.Authenticated {
			status = "Success"
		} else if !l.Active {
			status = "Failed"
		}

		activity := map[string]interface{}{
			"id":              l.ID,
			"subject":         l.Subject,
			"client_id":       l.ClientID,
			"saml_request_id": l.SAMLRequestID,
			"status":          status,
			"timestamp":       l.CreatedAt,
		}
		stats.RecentActivity = append(stats.RecentActivity, activity)
	}

	c.JSON(http.StatusOK, stats)
}

// ListTenants godoc
// @Summary List Tenants
// @Description Lists all tenants configured within the identity hub.
// @Tags Tenants
// @Produce json
// @Security BearerAuth
// @Success 200 {array} payload.TenantResponse
// @Failure 500 {object} payload.AppError "Failed to retrieve tenants"
// @Router /admin/management/tenants [get]
func (h *ManagementHandler) ListTenants(c *gin.Context) {
	tenants, err := h.TenantUse.ListTenants(c.Request.Context())
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "Tenants", "list", err))
		return
	}
	c.JSON(http.StatusOK, tenants)
}

// GetTenant godoc
// @Summary Get Tenant
// @Description Retrieves a specific tenant by its ID.
// @Tags Tenants
// @Produce json
// @Security BearerAuth
// @Param id path string true "Tenant ID"
// @Success 200 {object} model.Tenant
// @Failure 404 {object} payload.AppError "Tenant not found"
// @Router /admin/management/tenants/{id} [get]
func (h *ManagementHandler) GetTenant(c *gin.Context) {
	id := c.Param("id")
	tenant, err := h.TenantUse.GetTenant(c.Request.Context(), id)
	if err != nil {
		c.Error(payload.NewNotFoundAppError("Tenant", err))
		return
	}
	c.JSON(http.StatusOK, tenant)
}

// CreateTenant godoc
// @Summary Create Tenant
// @Description Creates a new isolated tenant environment with strict data boundaries.
// @Tags Tenants
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body payload.CreateTenantRequest true "Tenant Information"
// @Success 201 {object} model.Tenant
// @Failure 400 {object} payload.AppError "Invalid request payload"
// @Failure 500 {object} payload.AppError "Failed to create tenant"
// @Router /admin/management/tenants [post]
func (h *ManagementHandler) CreateTenant(c *gin.Context) {
	var tenantReq payload.CreateTenantRequest
	if err := c.ShouldBindJSON(&tenantReq); err != nil {
		c.Error(payload.NewValidationAppError(err))
		return
	}

	tenant := &model.Tenant{
		ID:          tenantReq.ID,
		Name:        tenantReq.Name,
		DisplayName: tenantReq.DisplayName,
		Description: tenantReq.Description,
	}
	tenant, err := h.TenantUse.CreateTenant(c.Request.Context(), tenant, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "Tenant", "create", err))
		return
	}
	logger.FromGin(c).Info("Tenant created successfully", zap.String("target_tenant_id", tenant.ID), zap.String("tenant_name", tenant.Name))
	c.JSON(http.StatusCreated, tenant)
}

// UpdateTenant godoc
// @Summary Update Tenant
// @Description Updates an existing tenant's details.
// @Tags Tenants
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Tenant ID"
// @Param request body payload.CreateTenantRequest true "Tenant Update Information"
// @Success 200 {object} map[string]string "status: updated"
// @Failure 400 {object} payload.AppError "Invalid request payload"
// @Failure 500 {object} payload.AppError "Failed to update tenant"
// @Router /admin/management/tenants/{id} [put]
func (h *ManagementHandler) UpdateTenant(c *gin.Context) {
	id := c.Param("id")
	var req payload.CreateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(payload.NewValidationAppError(err))
		return
	}

	tenant := &model.Tenant{
		ID:          req.ID,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
	}
	err := h.TenantUse.UpdateTenant(c.Request.Context(), tenant, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "Tenant", "update", err))
		return
	}
	logger.FromGin(c).Info("Tenant updated successfully", zap.String("target_tenant_id", id))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// DeleteTenant godoc
// @Summary DeleteByClient Tenant
// @Description Performs a cascade delete of a tenant and all its associated resources. The default tenant cannot be deleted.
// @Tags Tenants
// @Produce json
// @Security BearerAuth
// @Param id path string true "Tenant ID"
// @Success 200 {object} map[string]string "message: Tenant and all associated resources deleted successfully"
// @Failure 400 {object} payload.AppError "Cannot delete the default tenant"
// @Failure 500 {object} payload.AppError "Failed to cascade delete tenant"
// @Router /admin/management/tenants/{id} [delete]
func (h *ManagementHandler) DeleteTenant(c *gin.Context) {
	tenantID := c.Param("id")

	if tenantID == "default" {
		c.Error(payload.NewDetailedAppError(http.StatusBadRequest, "default_tenant_protected", "The default tenant cannot be deleted.", "Delete a non-default tenant or keep the default tenant in place.", nil, nil))
		return
	}

	err := h.TenantUse.DeleteTenant(c.Request.Context(), tenantID, c.ClientIP(), c.Request.UserAgent())

	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "Tenant", "delete", err))
		return
	}

	logger.FromGin(c).Info("Tenant deleted successfully", zap.String("target_tenant_id", tenantID))
	c.JSON(http.StatusOK, gin.H{"message": "Tenant and all associated resources deleted successfully"})
}

// CreateClient godoc
// @Summary Create OIDC Client
// @Description Registers a new OAuth2/OIDC client under the specified tenant enforcing OAuth 2.1 standards.
// @Tags OAuth2 Clients
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body payload.CreateOAuth2ClientRequest true "Client Configuration"
// @Success 201 {object} payload.CreateOAuth2ClientRequest
// @Failure 400 {object} payload.AppError "Invalid request payload or tenant not found"
// @Failure 500 {object} payload.AppError "Failed to create OIDC req"
// @Router /admin/management/clients [post]
func (h *ManagementHandler) CreateClient(c *gin.Context) {
	var req payload.CreateOAuth2ClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(payload.NewValidationAppError(err))
		return
	}

	realTenantID, ok := h.resolveTenantID(c, req.TenantID)
	if !ok {
		return
	}
	req.TenantID = realTenantID

	req.ResponseModes = []string{"query", "fragment", "form_post"}

	client := &model.OAuth2Client{
		ID:                      req.ID,
		TenantID:                req.TenantID,
		Name:                    req.Name,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		ResponseModes:           req.ResponseModes,
		Scopes:                  req.Scopes,
		Audience:                req.Audience,
		Public:                  req.Public,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		EnforcePKCE:             req.EnforcePKCE,
		AllowedCORSOrigins:      req.AllowedCORSOrigins,
		PostLogoutRedirectURIs:  req.PostLogoutRedirectURIs,
		BackchannelLogoutURI:    req.BackchannelLogoutURI,
		SubjectType:             req.SubjectType,
		JSONWebKeys:             req.JWKS,
	}
	_, _, err := h.OAuth2ClientUse.CreateClient(c.Request.Context(), client, req.Secret, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "OIDC client", "create", err))
		return
	}
	logger.FromGin(c).Info("OIDC client created successfully", zap.String("client_id", req.ID), zap.String("target_tenant_id", req.TenantID), zap.String("protocol", "oidc"))
	c.JSON(http.StatusCreated, req)
}

// ListClients godoc
// @Summary List All OIDC Clients
// @Description Lists all OAuth2/OIDC clients across the system. Secrets are masked.
// @Tags OAuth2 Clients
// @Produce json
// @Security BearerAuth
// @Success 200 {array} model.OAuth2Client
// @Failure 500 {object} payload.AppError "Failed to retrieve clients"
// @Router /admin/management/clients [get]
func (h *ManagementHandler) ListClients(c *gin.Context) {
	clients, err := h.OAuth2ClientUse.ListClients(c.Request.Context(), "")
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "OIDC clients", "list", err))
		return
	}
	for i := range clients {
		clients[i].Secret = "*****"
	}
	c.JSON(http.StatusOK, clients)
}

// ListClientsByTenant godoc
// @Summary List OIDC Clients By Tenant
// @Description Lists all OAuth2/OIDC clients for a specific tenant. Secrets are masked.
// @Tags OAuth2 Clients
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Success 200 {array} model.OAuth2Client
// @Failure 400 {object} payload.AppError "tenant_id is required"
// @Failure 500 {object} payload.AppError "Failed to retrieve clients for tenant"
// @Router /admin/management/tenants/{tenant_id}/clients [get]
func (h *ManagementHandler) ListClientsByTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.Error(payload.NewRequiredQueryParamError("tenant_id"))
		return
	}

	clients, err := h.OAuth2ClientUse.ListClients(c.Request.Context(), tenantID)
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "OIDC clients", "list", err))
		return
	}

	for i := range clients {
		clients[i].Secret = "*****"
	}

	c.JSON(http.StatusOK, clients)
}

// GetClient godoc
// @Summary Get OIDC Client
// @Description Retrieves details of a specific OAuth2/OIDC client. Secrets are masked.
// @Tags OAuth2 Clients
// @Produce json
// @Security BearerAuth
// @Param id path string true "Client ID"
// @Success 200 {object} model.OAuth2Client
// @Failure 404 {object} payload.AppError "OIDC Client not found"
// @Router /admin/management/clients/{id} [get]
func (h *ManagementHandler) GetClient(c *gin.Context) {
	id := c.Param("id")
	client, err := h.OAuth2ClientUse.GetClient(c.Request.Context(), id)
	if err != nil {
		c.Error(payload.NewNotFoundAppError("OIDC client", err))
		return
	}
	client.Secret = "*****"
	c.JSON(http.StatusOK, client)
}

// UpdateClient godoc
// @Summary Update OIDC Client
// @Description Updates an existing OAuth2/OIDC client. Pass "*****" or empty string to keep the existing secret.
// @Tags OAuth2 Clients
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Client ID"
// @Param request body payload.CreateOAuth2ClientRequest true "Client Update Configuration"
// @Success 200 {object} map[string]string "status: updated"
// @Failure 400 {object} payload.AppError "Invalid request payload"
// @Failure 404 {object} payload.AppError "OIDC Client not found"
// @Failure 500 {object} payload.AppError "Failed to update OIDC client"
// @Router /admin/management/clients/{id} [put]
func (h *ManagementHandler) UpdateClient(c *gin.Context) {
	id := c.Param("id")
	var req payload.CreateOAuth2ClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(payload.NewValidationAppError(err))
		return
	}

	client, err := h.OAuth2ClientUse.GetClient(c.Request.Context(), id)
	if err != nil {
		c.Error(payload.NewNotFoundAppError("OIDC client", err))
		return
	}

	clientToSave := &model.OAuth2Client{
		ID:                      req.ID,
		TenantID:                req.TenantID,
		Name:                    req.Name,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		ResponseModes:           req.ResponseModes,
		Scopes:                  req.Scopes,
		Audience:                req.Audience,
		Public:                  req.Public,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		EnforcePKCE:             req.EnforcePKCE,
		AllowedCORSOrigins:      req.AllowedCORSOrigins,
		PostLogoutRedirectURIs:  req.PostLogoutRedirectURIs,
		BackchannelLogoutURI:    req.BackchannelLogoutURI,
		SubjectType:             req.SubjectType,
	}

	// Secret handling (Keep existing if not changed)
	clientToSave.Secret = client.Secret
	unhashedSecret := ""
	if req.Secret != "" && req.Secret != "*****" {
		unhashedSecret = req.Secret
	}

	_, _, err = h.OAuth2ClientUse.UpdateClient(c.Request.Context(), clientToSave, unhashedSecret, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "OIDC client", "update", err))
		return
	}
	logger.FromGin(c).Info("OIDC client updated successfully", zap.String("client_id", id), zap.String("protocol", "oidc"))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// DeleteClient godoc
// @Summary DeleteByClient OIDC Client
// @Description Deletes an OAuth2/OIDC client from a specific tenant.
// @Tags OAuth2 Clients
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param id path string true "Client ID"
// @Success 204 "No Content"
// @Failure 500 {object} payload.AppError "Failed to delete OIDC client"
// @Router /admin/management/clients/{tenant_id}/{id} [delete]
func (h *ManagementHandler) DeleteClient(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	id := c.Param("id")

	err := h.OAuth2ClientUse.DeleteClient(c.Request.Context(), tenantID, id, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "OIDC client", "delete", err))
		return
	}

	logger.FromGin(c).Info("OIDC client deleted successfully", zap.String("client_id", id), zap.String("protocol", "oidc"))
	c.JSON(http.StatusNoContent, nil)
}

// ListSAMLClients godoc
// @Summary List All SAML Clients
// @Description Lists all SAML Service Providers globally across the hub.
// @Tags SAML Clients
// @Produce json
// @Security BearerAuth
// @Success 200 {array} model.SAMLClient
// @Failure 500 {object} payload.AppError "Failed to retrieve SAML clients"
// @Router /admin/management/saml-clients [get]
func (h *ManagementHandler) ListSAMLClients(c *gin.Context) {
	clients, err := h.SAMLClientUse.ListClients(c.Request.Context(), "")
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "SAML clients", "list", err))
		return
	}
	c.JSON(http.StatusOK, clients)
}

// ListSAMLClientsByTenant godoc
// @Summary List SAML Clients By Tenant
// @Description Lists all SAML Service Providers for a specific tenant.
// @Tags SAML Clients
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Success 200 {array} model.SAMLClient
// @Failure 400 {object} payload.AppError "tenant_id is required"
// @Failure 500 {object} payload.AppError "Failed to retrieve SAML clients for tenant"
// @Router /admin/management/saml-clients/tenant/{tenant_id} [get]
func (h *ManagementHandler) ListSAMLClientsByTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.Error(payload.NewRequiredQueryParamError("tenant_id"))
		return
	}

	clients, err := h.SAMLClientUse.ListClients(c.Request.Context(), tenantID)
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "SAML clients", "list", err))
		return
	}
	c.JSON(http.StatusOK, clients)
}

// GetSAMLClient godoc
// @Summary Get SAML Client
// @Description Retrieves details of a specific SAML Service Provider.
// @Tags SAML Clients
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param id path string true "Client ID"
// @Success 200 {object} model.SAMLClient
// @Failure 404 {object} payload.AppError "SAML Client not found"
// @Router /admin/management/saml-clients/{tenant_id}/{id} [get]
func (h *ManagementHandler) GetSAMLClient(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	id := c.Param("id")
	client, err := h.SAMLClientUse.GetClient(c.Request.Context(), tenantID, id)
	if err != nil {
		c.Error(payload.NewNotFoundAppError("SAML client", err))
		return
	}
	c.JSON(http.StatusOK, client)
}

// CreateSAMLClient godoc
// @Summary Create SAML Client
// @Description Registers a legacy SAML Service Provider in the system for federation.
// @Tags SAML Clients
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body payload.CreateSAMLClientRequest true "SAML Client Configuration"
// @Success 201 {object} payload.CreateSAMLClientRequest
// @Failure 400 {object} payload.AppError "Invalid request payload or tenant not found"
// @Failure 500 {object} payload.AppError "Failed to create SAML client"
// @Router /admin/management/saml-clients [post]
func (h *ManagementHandler) CreateSAMLClient(c *gin.Context) {
	var client payload.CreateSAMLClientRequest
	if err := c.ShouldBindJSON(&client); err != nil {
		c.Error(payload.NewValidationAppError(err))
		return
	}

	realTenantID, ok := h.resolveTenantID(c, client.TenantID)
	if !ok {
		return
	}
	client.TenantID = realTenantID

	clientToSave := &model.SAMLClient{
		TenantID:                client.TenantID,
		Name:                    client.Name,
		EntityID:                client.EntityID,
		ACSURL:                  client.ACSURL,
		SLOURL:                  client.SLOURL,
		SPCertificate:           client.SPCertificate,
		SPEncryptionCertificate: client.SPEncryptionCertificate,
		MetadataURL:             client.MetadataURL,
		AttributeMapping:        client.AttributeMapping,
		ForceAuthn:              client.ForceAuthn,
		SignResponse:            client.SignResponse,
		SignAssertion:           client.SignAssertion,
		EncryptAssertion:        client.EncryptAssertion,
		AllowedScopes:           client.AllowedScopes,
		Active:                  true,
	}

	createdClient, err := h.SAMLClientUse.CreateClient(c.Request.Context(), clientToSave, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "SAML client", "create", err))
		return
	}
	logger.FromGin(c).Info("SAML client created successfully", zap.String("client_id", createdClient.ID), zap.String("target_tenant_id", client.TenantID), zap.String("protocol", "saml"))
	c.JSON(http.StatusCreated, client)
}

// UpdateSAMLClient godoc
// @Summary Update SAML Client
// @Description Updates an existing SAML Service Provider. Automatically pulls metadata if MetadataURL is provided.
// @Tags SAML Clients
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Client ID"
// @Param request body payload.CreateSAMLClientRequest true "SAML Client Update Configuration"
// @Success 200 {object} map[string]string "status: updated"
// @Failure 400 {object} payload.AppError "Invalid request payload or missing required fields"
// @Failure 500 {object} payload.AppError "Failed to update SAML client"
// @Router /admin/management/saml-clients/{id} [put]
func (h *ManagementHandler) UpdateSAMLClient(c *gin.Context) {
	id := c.Param("id")
	var req payload.CreateSAMLClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(payload.NewValidationAppError(err))
		return
	}

	client, err := h.SAMLClientUse.GetClient(c.Request.Context(), req.TenantID, id)
	if err != nil {
		c.Error(payload.NewNotFoundAppError("SAML client", err))
		return
	}

	client.TenantID = req.TenantID
	client.Name = req.Name
	client.ACSURL = req.ACSURL
	client.SPCertificate = req.SPCertificate
	client.AttributeMapping = req.AttributeMapping
	client.ForceAuthn = req.ForceAuthn
	client.SignResponse = req.SignResponse
	client.SignAssertion = req.SignAssertion
	client.EncryptAssertion = req.EncryptAssertion
	client.AllowedScopes = req.AllowedScopes

	if client.MetadataURL != "" {
		descriptor, _, err := shyntrsaml.FetchAndParseMetadata(
			c.Request.Context(),
			client.TenantID,
			client.MetadataURL,
			h.OutboundGuard,
		)
		if err != nil {
			payload.AbortWithAppError(c, payload.NewOperationAppError(http.StatusBadRequest, "SAML client metadata", "process", err))
			return
		}

		if descriptor != nil {
			if client.EntityID == "" {
				client.EntityID = descriptor.EntityID
			}

			if len(descriptor.SPSSODescriptors) > 0 {
				sp := descriptor.SPSSODescriptors[0]
				if client.ACSURL == "" {
					for _, acs := range sp.AssertionConsumerServices {
						client.ACSURL = acs.Location
						if acs.Binding == saml.HTTPPostBinding {
							break
						}
					}
				}
				if client.SLOURL == "" {
					for _, slo := range sp.SingleLogoutServices {
						client.SLOURL = slo.Location
						if slo.Binding == saml.HTTPRedirectBinding {
							break
						}
					}
				}

				for _, kd := range sp.KeyDescriptors {
					if len(kd.KeyInfo.X509Data.X509Certificates) > 0 {
						certData := shyntrsaml.FormatCertificate(kd.KeyInfo.X509Data.X509Certificates[0].Data)

						if kd.Use == "signing" || kd.Use == "" {
							if client.SPCertificate == "" {
								client.SPCertificate = certData
							}
						}

						if kd.Use == "encryption" || kd.Use == "" {
							if client.SPEncryptionCertificate == "" {
								client.SPEncryptionCertificate = certData
							}
						}
					}
				}
			}
		}
	}

	if client.EntityID == "" || client.ACSURL == "" {
		payload.AbortWithAppError(c, payload.NewDetailedAppError(http.StatusBadRequest, "missing_required_fields", "The SAML client request must include entity_id and acs_url when metadata_url is not provided.", "Provide entity_id and acs_url, or send a valid metadata_url.", []payload.FieldError{{Field: "entity_id", Message: "This field is required when metadata_url is empty."}, {Field: "acs_url", Message: "This field is required when metadata_url is empty."}}, nil))
		return
	}

	err = h.SAMLClientUse.UpdateClient(c.Request.Context(), client, c.ClientIP(), c.Request.UserAgent())

	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "SAML client", "update", err))
		return
	}
	logger.FromGin(c).Info("SAML client updated successfully", zap.String("entity_id", req.EntityID), zap.String("target_tenant_id", req.TenantID), zap.String("protocol", "saml"))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// DeleteSAMLClient godoc
// @Summary DeleteByClient SAML Client
// @Description Removes a SAML Service Provider from a specific tenant.
// @Tags SAML Clients
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param id path string true "Client ID"
// @Success 204 "No Content"
// @Failure 500 {object} payload.AppError "Failed to delete SAML client"
// @Router /admin/management/saml-clients/{tenant_id}/{id} [delete]
func (h *ManagementHandler) DeleteSAMLClient(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	id := c.Param("id")
	err := h.SAMLClientUse.DeleteClient(c.Request.Context(), tenantID, id, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "SAML client", "delete", err))
		return
	}
	logger.FromGin(c).Info("SAML client deleted successfully", zap.String("client_id", id), zap.String("protocol", "saml"))
	c.JSON(http.StatusNoContent, nil)
}

// --- SAML Connection Management (Identity Providers) ---

// CreateSAMLConnection godoc
// @Summary Create SAML Connection (IdP)
// @Description Registers an external SAML Identity Provider for federated authentication.
// @Tags SAML Connections
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body payload.CreateSAMLConnectionRequest true "SAML Connection Configuration"
// @Success 201 {object} payload.CreateSAMLConnectionRequest
// @Failure 400 {object} payload.AppError "Invalid request payload or missing metadata"
// @Failure 500 {object} payload.AppError "Failed to create SAML connection"
// @Router /admin/management/saml-connections [post]
func (h *ManagementHandler) CreateSAMLConnection(c *gin.Context) {
	var conn payload.CreateSAMLConnectionRequest
	if err := c.ShouldBindJSON(&conn); err != nil {
		c.Error(payload.NewValidationAppError(err))
		return
	}

	realTenantID, ok := h.resolveTenantID(c, conn.TenantID)
	if !ok {
		return
	}
	conn.TenantID = realTenantID

	if conn.MetadataURL == "" && conn.IdpMetadataXML == "" {
		c.Error(payload.NewDetailedAppError(http.StatusBadRequest, "missing_metadata", "The SAML connection request must include metadata_url or idp_metadata_xml.", "Provide a valid metadata_url or inline idp_metadata_xml and send the request again.", []payload.FieldError{{Field: "metadata_url", Message: "Provide this field or idp_metadata_xml."}, {Field: "idp_metadata_xml", Message: "Provide this field or metadata_url."}}, nil))
		return
	}

	connToSave := &model.SAMLConnection{
		ID:                       "",
		TenantID:                 conn.TenantID,
		Name:                     conn.Name,
		IdpMetadataXML:           conn.IdpMetadataXML,
		IdpEntityID:              conn.IdpEntityID,
		IdpSingleSignOn:          conn.IdpSingleSignOn,
		IdpSloUrl:                conn.IdpSloUrl,
		IdpCertificate:           conn.IdpCertificate,
		IdpEncryptionCertificate: conn.IdpEncryptionCertificate,
		MetadataURL:              conn.MetadataURL,
		SPPrivateKey:             conn.SPPrivateKey,
		AttributeMapping:         conn.AttributeMapping,
		ForceAuthn:               conn.ForceAuthn,
		SignRequest:              conn.SignRequest,
		Active:                   true,
	}

	connection, err := h.SAMLConnUse.CreateConnection(c.Request.Context(), connToSave, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "SAML connection", "create", err))
		return
	}
	logger.FromGin(c).Info("SAML connection created successfully", zap.String("entity_id", connection.IdpEntityID), zap.String("target_tenant_id", connection.TenantID), zap.String("protocol", "saml"))
	c.JSON(http.StatusCreated, conn)
}

// ListSAMLConnections godoc
// @Summary List All SAML Connections
// @Description Lists all federated SAML Identity Providers.
// @Tags SAML Connections
// @Produce json
// @Security BearerAuth
// @Success 200 {array} model.SAMLConnection
// @Failure 500 {object} payload.AppError "Failed to retrieve SAML connections"
// @Router /admin/management/saml-connections [get]
func (h *ManagementHandler) ListSAMLConnections(c *gin.Context) {
	connections, err := h.SAMLConnUse.ListConnections(c.Request.Context(), "")
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "SAML connections", "list", err))
		return
	}
	c.JSON(http.StatusOK, connections)
}

// ListSAMLConnectionsByTenant godoc
// @Summary List SAML Connections By Tenant
// @Description Lists all federated SAML Identity Providers for a specific tenant.
// @Tags SAML Connections
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Success 200 {array} model.SAMLConnection
// @Failure 400 {object} payload.AppError "tenant_id is required"
// @Failure 500 {object} payload.AppError "Failed to retrieve SAML connections for tenant"
// @Router /admin/management/tenants/{tenant_id}/saml-connections [get]
func (h *ManagementHandler) ListSAMLConnectionsByTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.Error(payload.NewRequiredQueryParamError("tenant_id"))
		return
	}

	connections, err := h.SAMLConnUse.ListConnections(c.Request.Context(), tenantID)
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "SAML connections", "list", err))
		return
	}
	c.JSON(http.StatusOK, connections)
}

// GetSAMLConnection godoc
// @Summary Get SAML Connection
// @Description Retrieves details of a specific SAML Identity Provider.
// @Tags SAML Connections
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param id path string true "Connection ID"
// @Success 200 {object} model.SAMLConnection
// @Failure 404 {object} payload.AppError "SAML Connection not found"
// @Router /admin/management/saml-connections/{tenant_id}/{id} [get]
func (h *ManagementHandler) GetSAMLConnection(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	id := c.Param("id")
	conn, err := h.SAMLConnUse.GetConnection(c.Request.Context(), tenantID, id)
	if err != nil {
		c.Error(payload.NewNotFoundAppError("SAML connection", err))
		return
	}
	c.JSON(http.StatusOK, conn)
}

// UpdateSAMLConnection godoc
// @Summary Update SAML Connection
// @Description Updates an existing SAML Identity Provider.
// @Tags SAML Connections
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Connection ID"
// @Param request body payload.CreateSAMLConnectionRequest true "SAML Connection Update Configuration"
// @Success 200 {object} map[string]string "status: updated"
// @Failure 400 {object} payload.AppError "Invalid request payload"
// @Failure 500 {object} payload.AppError "Failed to update SAML connection"
// @Router /admin/management/saml-connections/{id} [put]
func (h *ManagementHandler) UpdateSAMLConnection(c *gin.Context) {
	var req payload.CreateSAMLConnectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(payload.NewValidationAppError(err))
		return
	}

	updateData := model.SAMLConnection{
		ID:                       req.ID,
		TenantID:                 req.TenantID,
		Name:                     req.Name,
		IdpMetadataXML:           req.IdpMetadataXML,
		IdpEntityID:              req.IdpEntityID,
		IdpSingleSignOn:          req.IdpSingleSignOn,
		IdpSloUrl:                req.IdpSloUrl,
		IdpCertificate:           req.IdpCertificate,
		IdpEncryptionCertificate: req.IdpEncryptionCertificate,
		MetadataURL:              req.MetadataURL,
		SPPrivateKey:             req.SPPrivateKey,
		AttributeMapping:         req.AttributeMapping,
		ForceAuthn:               req.ForceAuthn,
		SignRequest:              req.SignRequest,
		Active:                   true,
	}

	err := h.SAMLConnUse.UpdateConnection(c.Request.Context(), &updateData, c.ClientIP(), c.Request.UserAgent())

	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "SAML connection", "update", err))
		return
	}
	logger.FromGin(c).Info("SAML connection updated successfully", zap.String("entity_id", updateData.IdpEntityID), zap.String("target_tenant_id", updateData.TenantID), zap.String("protocol", "saml"))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// DeleteSAMLConnection godoc
// @Summary DeleteByClient SAML Connection
// @Description Deletes a federated SAML Identity Provider from a tenant.
// @Tags SAML Connections
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param id path string true "Connection ID"
// @Success 204 "No Content"
// @Failure 500 {object} payload.AppError "Failed to delete SAML connection"
// @Router /admin/management/saml-connections/{tenant_id}/{id} [delete]
func (h *ManagementHandler) DeleteSAMLConnection(c *gin.Context) {
	id := c.Param("id")
	tenantID := c.Param("tenant_id")
	err := h.SAMLConnUse.DeleteConnection(c.Request.Context(), tenantID, id, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "SAML connection", "delete", err))
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// --- OIDC Connection Management ---

// CreateOIDCConnection godoc
// @Summary Create OIDC Connection (IdP)
// @Description Registers an external OpenID Connect Identity Provider for federated authentication.
// @Tags OIDC Connections
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body payload.CreateOIDCConnectionRequest true "OIDC Connection Configuration"
// @Success 201 {object} payload.CreateOIDCConnectionRequest
// @Failure 400 {object} payload.AppError "Invalid request payload"
// @Failure 500 {object} payload.AppError "Failed to create OIDC connection"
// @Router /admin/management/oidc-connections [post]
func (h *ManagementHandler) CreateOIDCConnection(c *gin.Context) {
	var conn payload.CreateOIDCConnectionRequest
	if err := c.ShouldBindJSON(&conn); err != nil {
		c.Error(payload.NewValidationAppError(err))
		return
	}

	realTenantID, ok := h.resolveTenantID(c, conn.TenantID)
	if !ok {
		return
	}
	conn.TenantID = realTenantID

	connection := &model.OIDCConnection{
		ID:                    conn.ID,
		TenantID:              conn.TenantID,
		Name:                  conn.Name,
		IssuerURL:             conn.IssuerURL,
		ClientID:              conn.ClientID,
		ClientSecret:          conn.ClientSecret,
		AuthorizationEndpoint: conn.AuthorizationEndpoint,
		TokenEndpoint:         conn.TokenEndpoint,
		UserInfoEndpoint:      conn.UserInfoEndpoint,
		JWKSURI:               conn.JWKSURI,
		EndSessionEndpoint:    conn.EndSessionEndpoint,
		Scopes:                conn.Scopes,
		AttributeMapping:      conn.AttributeMapping,
		Active:                true,
	}

	savedConn, err := h.OIDCConnUse.CreateConnection(c.Request.Context(), connection, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "OIDC connection", "create", err))
		return
	}
	logger.FromGin(c).Info("OIDC connection created successfully", zap.String("client_id", savedConn.ClientID), zap.String("target_tenant_id", savedConn.TenantID), zap.String("protocol", "oidc"))
	c.JSON(http.StatusCreated, conn)
}

// ListOIDCConnections godoc
// @Summary List All OIDC Connections
// @Description Lists all federated OIDC Identity Providers.
// @Tags OIDC Connections
// @Produce json
// @Security BearerAuth
// @Success 200 {array} model.OIDCConnection
// @Failure 500 {object} payload.AppError "Failed to retrieve OIDC connections"
// @Router /admin/management/oidc-connections [get]
func (h *ManagementHandler) ListOIDCConnections(c *gin.Context) {
	connections, err := h.OIDCConnUse.ListConnections(c.Request.Context(), "")
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "OIDC connections", "list", err))
		return
	}
	c.JSON(http.StatusOK, connections)
}

// ListOIDCConnectionsByTenant godoc
// @Summary List OIDC Connections By Tenant
// @Description Lists all federated OIDC Identity Providers for a specific tenant.
// @Tags OIDC Connections
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Success 200 {array} model.OIDCConnection
// @Failure 400 {object} payload.AppError "tenant_id is required"
// @Failure 500 {object} payload.AppError "Failed to retrieve OIDC connections for tenant"
// @Router /admin/management/tenants/{tenant_id}/oidc-connections [get]
func (h *ManagementHandler) ListOIDCConnectionsByTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.Error(payload.NewRequiredQueryParamError("tenant_id"))
		return
	}

	connections, err := h.OIDCConnUse.ListConnections(c.Request.Context(), tenantID)
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "OIDC connections", "list", err))
		return
	}
	c.JSON(http.StatusOK, connections)
}

// GetOIDCConnection godoc
// @Summary Get OIDC Connection
// @Description Retrieves details of a specific OIDC Identity Provider.
// @Tags OIDC Connections
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param id path string true "Connection ID"
// @Success 200 {object} model.OIDCConnection
// @Failure 404 {object} payload.AppError "OIDC Connection not found"
// @Router /admin/management/oidc-connections/{tenant_id}/{id} [get]
func (h *ManagementHandler) GetOIDCConnection(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	id := c.Param("id")
	connection, err := h.OIDCConnUse.GetConnection(c.Request.Context(), tenantID, id)
	if err != nil {
		c.Error(payload.NewNotFoundAppError("OIDC connection", err))
		return
	}
	c.JSON(http.StatusOK, connection)
}

// UpdateOIDCConnection godoc
// @Summary Update OIDC Connection
// @Description Updates an existing OIDC Identity Provider.
// @Tags OIDC Connections
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Connection ID"
// @Param request body payload.CreateOIDCConnectionRequest true "OIDC Connection Update Configuration"
// @Success 200 {object} map[string]string "status: updated"
// @Failure 400 {object} payload.AppError "Invalid request payload"
// @Failure 500 {object} payload.AppError "Failed to update OIDC connection"
// @Router /admin/management/oidc-connections/{id} [put]
func (h *ManagementHandler) UpdateOIDCConnection(c *gin.Context) {
	var req payload.CreateOIDCConnectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(payload.NewValidationAppError(err))
		return
	}

	updateData := model.OIDCConnection{
		ID:                    req.ID,
		TenantID:              req.TenantID,
		Name:                  req.Name,
		IssuerURL:             req.IssuerURL,
		ClientID:              req.ClientID,
		ClientSecret:          req.ClientSecret,
		AuthorizationEndpoint: req.AuthorizationEndpoint,
		TokenEndpoint:         req.TokenEndpoint,
		UserInfoEndpoint:      req.UserInfoEndpoint,
		JWKSURI:               req.JWKSURI,
		EndSessionEndpoint:    req.EndSessionEndpoint,
		Scopes:                req.Scopes,
		AttributeMapping:      req.AttributeMapping,
	}

	err := h.OIDCConnUse.UpdateConnection(c.Request.Context(), &updateData, c.ClientIP(), c.Request.UserAgent())

	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "OIDC connection", "update", err))
		return
	}
	logger.FromGin(c).Info("OIDC connection updated successfully", zap.String("client_id", updateData.ClientID), zap.String("target_tenant_id", updateData.TenantID), zap.String("protocol", "oidc"))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// DeleteOIDCConnection godoc
// @Summary DeleteByClient OIDC Connection
// @Description Deletes a federated OIDC Identity Provider from a tenant.
// @Tags OIDC Connections
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param id path string true "Connection ID"
// @Success 204 "No Content"
// @Failure 500 {object} payload.AppError "Failed to delete OIDC connection"
// @Router /admin/management/oidc-connections/{tenant_id}/{id} [delete]
func (h *ManagementHandler) DeleteOIDCConnection(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	id := c.Param("id")
	err := h.OIDCConnUse.DeleteConnection(c.Request.Context(), tenantID, id, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "OIDC connection", "delete", err))
		return
	}
	logger.FromGin(c).Info("OIDC connection deleted successfully", zap.String("client_id", id), zap.String("protocol", "oidc"))
	c.JSON(http.StatusNoContent, nil)
}

// --- LDAP Connection Management ---

// CreateLDAPConnection godoc
// @Summary Create LDAP Connection (IdP)
// @Description Registers an external LDAP/Active-Directory Identity Provider for federated authentication.
// @Tags LDAP Connections
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body payload.CreateLDAPConnectionRequest true "LDAP Connection Configuration"
// @Success 201 {object} payload.LDAPConnectionResponse
// @Failure 400 {object} payload.AppError "Invalid request payload"
// @Failure 500 {object} payload.AppError "Failed to create LDAP connection"
// @Router /admin/management/ldap-connections [post]
func (h *ManagementHandler) CreateLDAPConnection(c *gin.Context) {
	var req payload.CreateLDAPConnectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(payload.NewValidationAppError(err))
		return
	}

	realTenantID, ok := h.resolveTenantID(c, req.TenantID)
	if !ok {
		return
	}
	req.TenantID = realTenantID

	conn := req.ToDomain()
	saved, err := h.LDAPConnUse.CreateConnection(c.Request.Context(), conn, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "LDAP connection", "create", err))
		return
	}
	logger.FromGin(c).Info("LDAP connection created successfully",
		zap.String("connection_id", saved.ID),
		zap.String("target_tenant_id", saved.TenantID),
		zap.String("protocol", "ldap"),
	)
	c.JSON(http.StatusCreated, payload.FromDomainLDAPConnection(saved))
}

// ListLDAPConnections godoc
// @Summary List All LDAP Connections
// @Description Lists all federated LDAP Identity Providers.
// @Tags LDAP Connections
// @Produce json
// @Security BearerAuth
// @Success 200 {array} payload.LDAPConnectionResponse
// @Failure 500 {object} payload.AppError "Failed to retrieve LDAP connections"
// @Router /admin/management/ldap-connections [get]
func (h *ManagementHandler) ListLDAPConnections(c *gin.Context) {
	connections, err := h.LDAPConnUse.ListConnections(c.Request.Context(), "")
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "LDAP connections", "list", err))
		return
	}
	resp := make([]*payload.LDAPConnectionResponse, 0, len(connections))
	for _, conn := range connections {
		resp = append(resp, payload.FromDomainLDAPConnection(conn))
	}
	c.JSON(http.StatusOK, resp)
}

// ListLDAPConnectionsByTenant godoc
// @Summary List LDAP Connections By Tenant
// @Description Lists all federated LDAP Identity Providers for a specific tenant.
// @Tags LDAP Connections
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Success 200 {array} payload.LDAPConnectionResponse
// @Failure 400 {object} payload.AppError "tenant_id is required"
// @Failure 500 {object} payload.AppError "Failed to retrieve LDAP connections for tenant"
// @Router /admin/management/tenants/{tenant_id}/ldap-connections [get]
func (h *ManagementHandler) ListLDAPConnectionsByTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.Error(payload.NewRequiredQueryParamError("tenant_id"))
		return
	}
	connections, err := h.LDAPConnUse.ListConnections(c.Request.Context(), tenantID)
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "LDAP connections", "list", err))
		return
	}
	resp := make([]*payload.LDAPConnectionResponse, 0, len(connections))
	for _, conn := range connections {
		resp = append(resp, payload.FromDomainLDAPConnection(conn))
	}
	c.JSON(http.StatusOK, resp)
}

// GetLDAPConnection godoc
// @Summary Get LDAP Connection
// @Description Retrieves details of a specific LDAP Identity Provider. BindPassword is never returned.
// @Tags LDAP Connections
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param id path string true "Connection ID"
// @Success 200 {object} payload.LDAPConnectionResponse
// @Failure 404 {object} payload.AppError "LDAP Connection not found"
// @Router /admin/management/ldap-connections/{tenant_id}/{id} [get]
func (h *ManagementHandler) GetLDAPConnection(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	id := c.Param("id")
	conn, err := h.LDAPConnUse.GetConnection(c.Request.Context(), tenantID, id)
	if err != nil {
		c.Error(payload.NewNotFoundAppError("LDAP connection", err))
		return
	}
	c.JSON(http.StatusOK, payload.FromDomainLDAPConnection(conn))
}

// UpdateLDAPConnection godoc
// @Summary Update LDAP Connection
// @Description Updates an existing LDAP Identity Provider. Pass empty string or "*****" for bind_password to keep the existing value.
// @Tags LDAP Connections
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Connection ID"
// @Param request body payload.CreateLDAPConnectionRequest true "LDAP Connection Update Configuration"
// @Success 200 {object} map[string]string "status: updated"
// @Failure 400 {object} payload.AppError "Invalid request payload"
// @Failure 500 {object} payload.AppError "Failed to update LDAP connection"
// @Router /admin/management/ldap-connections/{id} [put]
func (h *ManagementHandler) UpdateLDAPConnection(c *gin.Context) {
	var req payload.CreateLDAPConnectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(payload.NewValidationAppError(err))
		return
	}

	conn := req.ToDomain()
	// Use case handles the "*****" / empty password sentinel (keep existing).
	if err := h.LDAPConnUse.UpdateConnection(c.Request.Context(), conn, c.ClientIP(), c.Request.UserAgent()); err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "LDAP connection", "update", err))
		return
	}
	logger.FromGin(c).Info("LDAP connection updated successfully",
		zap.String("server_url", conn.ServerURL),
		zap.String("target_tenant_id", conn.TenantID),
		zap.String("protocol", "ldap"),
	)
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// DeleteLDAPConnection godoc
// @Summary Delete LDAP Connection
// @Description Deletes a federated LDAP Identity Provider from a tenant.
// @Tags LDAP Connections
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param id path string true "Connection ID"
// @Success 204 "No Content"
// @Failure 500 {object} payload.AppError "Failed to delete LDAP connection"
// @Router /admin/management/ldap-connections/{tenant_id}/{id} [delete]
func (h *ManagementHandler) DeleteLDAPConnection(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	id := c.Param("id")
	if err := h.LDAPConnUse.DeleteConnection(c.Request.Context(), tenantID, id, c.ClientIP(), c.Request.UserAgent()); err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "LDAP connection", "delete", err))
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// TestLDAPConnection godoc
// @Summary Test LDAP Connection
// @Description Verifies connectivity and service-account bind credentials for an LDAP connection.
// @Tags LDAP Connections
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param id path string true "Connection ID"
// @Success 200 {object} map[string]string "status: ok"
// @Failure 400 {object} payload.AppError "Connection test failed"
// @Router /admin/management/ldap-connections/{tenant_id}/{id}/test [post]
func (h *ManagementHandler) TestLDAPConnection(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	id := c.Param("id")
	if err := h.LDAPConnUse.TestConnection(c.Request.Context(), tenantID, id); err != nil {
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "LDAP connection", "test", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
