package handlers

import (
	"net/http"

	"github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/internal/adapters/http/dto"
	"github.com/nevzatcirak/shyntr/internal/adapters/http/response"
	"github.com/nevzatcirak/shyntr/internal/application/usecase"
	shyntrsaml "github.com/nevzatcirak/shyntr/internal/application/utils"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/ory/fosite"
	"go.uber.org/zap"
)

type ManagementHandler struct {
	FositeConfig     *fosite.Config
	OAuth2ClientUse  usecase.OAuth2ClientUseCase
	SAMLClientUse    usecase.SAMLClientUseCase
	SAMLConnUse      usecase.SAMLConnectionUseCase
	OIDCConnUse      usecase.OIDCConnectionUseCase
	OAuth2SessionUse usecase.OAuth2SessionUseCase
	AuthReq          usecase.AuthUseCase
	TenantUse        usecase.TenantUseCase
}

func NewManagementHandler(fositeCfg *fosite.Config, OAuth2ClientUse usecase.OAuth2ClientUseCase, SAMLClientUse usecase.SAMLClientUseCase,
	SAMLConnUse usecase.SAMLConnectionUseCase, AuthReq usecase.AuthUseCase,
	OAuth2SessionUse usecase.OAuth2SessionUseCase, OIDCConnUse usecase.OIDCConnectionUseCase,
	TenantUse usecase.TenantUseCase) *ManagementHandler {
	return &ManagementHandler{FositeConfig: fositeCfg, OAuth2ClientUse: OAuth2ClientUse, AuthReq: AuthReq,
		OAuth2SessionUse: OAuth2SessionUse, TenantUse: TenantUse, OIDCConnUse: OIDCConnUse,
		SAMLConnUse: SAMLConnUse, SAMLClientUse: SAMLClientUse}
}

func (h *ManagementHandler) resolveTenantID(c *gin.Context, inputID string) (string, bool) {
	if inputID == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "Tenant ID is required", nil))
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

	c.Error(response.NewAppError(http.StatusNotFound, "The specified tenant does not exist", nil))
	return "", false
}

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

func (h *ManagementHandler) ListTenants(c *gin.Context) {
	tenants, err := h.TenantUse.ListTenants(c.Request.Context())
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve tenants", err))
		return
	}
	c.JSON(http.StatusOK, tenants)
}

func (h *ManagementHandler) GetTenant(c *gin.Context) {
	id := c.Param("id")
	tenant, err := h.TenantUse.GetTenant(c.Request.Context(), id)
	if err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "Tenant not found", err))
		return
	}
	c.JSON(http.StatusOK, tenant)
}

func (h *ManagementHandler) CreateTenant(c *gin.Context) {
	var tenantReq dto.CreateTenantRequest
	if err := c.ShouldBindJSON(&tenantReq); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	tenant := &entity.Tenant{
		ID:          tenantReq.ID,
		Name:        tenantReq.Name,
		DisplayName: tenantReq.DisplayName,
		Description: tenantReq.Description,
	}
	tenant, err := h.TenantUse.CreateTenant(c.Request.Context(), tenant, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to create tenant", err))
		return
	}
	logger.FromGin(c).Info("Tenant created successfully", zap.String("target_tenant_id", tenant.ID), zap.String("tenant_name", tenant.Name))
	c.JSON(http.StatusCreated, tenant)
}

func (h *ManagementHandler) UpdateTenant(c *gin.Context) {
	id := c.Param("id")
	var req dto.CreateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	tenant := &entity.Tenant{
		ID:          req.ID,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
	}
	err := h.TenantUse.UpdateTenant(c.Request.Context(), tenant, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to update tenant", err))
		return
	}
	logger.FromGin(c).Info("Tenant updated successfully", zap.String("target_tenant_id", id))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *ManagementHandler) DeleteTenant(c *gin.Context) {
	tenantID := c.Param("id")

	if tenantID == "default" {
		c.Error(response.NewAppError(http.StatusBadRequest, "Cannot delete the default tenant", nil))
		return
	}

	err := h.TenantUse.DeleteTenant(c.Request.Context(), tenantID, c.ClientIP(), c.Request.UserAgent())

	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to cascade delete tenant", err))
		return
	}

	logger.FromGin(c).Info("Tenant deleted successfully", zap.String("target_tenant_id", tenantID))
	c.JSON(http.StatusOK, gin.H{"message": "Tenant and all associated resources deleted successfully"})
}

// --- OAuth2 Clients Management ---

func (h *ManagementHandler) CreateClient(c *gin.Context) {
	var req dto.CreateOAuth2ClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	realTenantID, ok := h.resolveTenantID(c, req.TenantID)
	if !ok {
		return
	}
	req.TenantID = realTenantID

	req.ResponseModes = []string{"query", "fragment", "form_post"}

	client := &entity.OAuth2Client{
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
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to create OIDC req", err))
		return
	}
	logger.FromGin(c).Info("OIDC client created successfully", zap.String("client_id", req.ID), zap.String("target_tenant_id", req.TenantID), zap.String("protocol", "oidc"))
	c.JSON(http.StatusCreated, req)
}

func (h *ManagementHandler) ListClients(c *gin.Context) {
	clients, err := h.OAuth2ClientUse.ListClients(c.Request.Context(), "")
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve clients", err))
		return
	}
	for i := range clients {
		clients[i].Secret = "*****"
	}
	c.JSON(http.StatusOK, clients)
}

func (h *ManagementHandler) ListClientsByTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "tenant_id is required", nil))
		return
	}

	clients, err := h.OAuth2ClientUse.ListClients(c.Request.Context(), tenantID)
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve clients for tenant", err))
		return
	}

	for i := range clients {
		clients[i].Secret = "*****"
	}

	c.JSON(http.StatusOK, clients)
}

func (h *ManagementHandler) GetClient(c *gin.Context) {
	id := c.Param("id")
	client, err := h.OAuth2ClientUse.GetClient(c.Request.Context(), id)
	if err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "OIDC Client not found", err))
		return
	}
	client.Secret = "*****"
	c.JSON(http.StatusOK, client)
}

func (h *ManagementHandler) UpdateClient(c *gin.Context) {
	id := c.Param("id")
	var req dto.CreateOAuth2ClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	client, err := h.OAuth2ClientUse.GetClient(c.Request.Context(), id)
	if err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "OIDC Client not found", err))
		return
	}

	clientToSave := &entity.OAuth2Client{
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
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to update OIDC client", err))
		return
	}
	logger.FromGin(c).Info("OIDC client updated successfully", zap.String("client_id", id), zap.String("protocol", "oidc"))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *ManagementHandler) DeleteClient(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	id := c.Param("id")

	err := h.OAuth2ClientUse.DeleteClient(c.Request.Context(), tenantID, id, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to delete OIDC client", err))
		return
	}

	logger.FromGin(c).Info("OIDC client deleted successfully", zap.String("client_id", id), zap.String("protocol", "oidc"))
	c.JSON(http.StatusNoContent, nil)
}

func (h *ManagementHandler) ListSAMLClients(c *gin.Context) {
	clients, err := h.SAMLClientUse.ListClients(c.Request.Context(), "")
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve SAML clients", err))
		return
	}
	c.JSON(http.StatusOK, clients)
}

func (h *ManagementHandler) ListSAMLClientsByTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "tenant_id is required", nil))
		return
	}

	clients, err := h.SAMLClientUse.ListClients(c.Request.Context(), tenantID)
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve SAML clients for tenant", err))
		return
	}
	c.JSON(http.StatusOK, clients)
}

func (h *ManagementHandler) GetSAMLClient(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	id := c.Param("id")
	client, err := h.SAMLClientUse.GetClient(c.Request.Context(), tenantID, id)
	if err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "SAML Client not found", err))
		return
	}
	c.JSON(http.StatusOK, client)
}

func (h *ManagementHandler) CreateSAMLClient(c *gin.Context) {
	var client dto.CreateSAMLClientRequest
	if err := c.ShouldBindJSON(&client); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	realTenantID, ok := h.resolveTenantID(c, client.TenantID)
	if !ok {
		return
	}
	client.TenantID = realTenantID

	clientToSave := &entity.SAMLClient{
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
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to create SAML client", err))
		return
	}
	logger.FromGin(c).Info("SAML client created successfully", zap.String("client_id", createdClient.ID), zap.String("target_tenant_id", client.TenantID), zap.String("protocol", "saml"))
	c.JSON(http.StatusCreated, client)
}

func (h *ManagementHandler) UpdateSAMLClient(c *gin.Context) {
	id := c.Param("id")
	var req dto.CreateSAMLClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	client, err := h.SAMLClientUse.GetClient(c.Request.Context(), req.TenantID, id)
	if err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "saml client not found", err))
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
		descriptor, _, err := shyntrsaml.FetchAndParseMetadata(client.MetadataURL)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Metadata URL: " + err.Error()})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "entity_id and acs_url are required if metadata_url is not provided"})
		return
	}

	err = h.SAMLClientUse.UpdateClient(c.Request.Context(), client, c.ClientIP(), c.Request.UserAgent())

	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to update SAML client", err))
		return
	}
	logger.FromGin(c).Info("SAML client updated successfully", zap.String("entity_id", req.EntityID), zap.String("target_tenant_id", req.TenantID), zap.String("protocol", "saml"))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *ManagementHandler) DeleteSAMLClient(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	id := c.Param("id")
	err := h.SAMLClientUse.DeleteClient(c.Request.Context(), tenantID, id, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to delete SAML client", err))
		return
	}
	logger.FromGin(c).Info("SAML client deleted successfully", zap.String("client_id", id), zap.String("protocol", "saml"))
	c.JSON(http.StatusNoContent, nil)
}

// --- SAML Connection Management (Identity Providers) ---

func (h *ManagementHandler) CreateSAMLConnection(c *gin.Context) {
	var conn dto.CreateSAMLConnectionRequest
	if err := c.ShouldBindJSON(&conn); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	realTenantID, ok := h.resolveTenantID(c, conn.TenantID)
	if !ok {
		return
	}
	conn.TenantID = realTenantID

	if conn.MetadataURL == "" && conn.IdpMetadataXML == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "Metadata URL or IdP Metadata XML is required", nil))
		return
	}

	connToSave := &entity.SAMLConnection{
		ID:                       conn.ID,
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
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to create SAML connection", err))
		return
	}
	logger.FromGin(c).Info("SAML connection created successfully", zap.String("entity_id", connection.IdpEntityID), zap.String("target_tenant_id", connection.TenantID), zap.String("protocol", "saml"))
	c.JSON(http.StatusCreated, conn)
}

func (h *ManagementHandler) ListSAMLConnections(c *gin.Context) {
	connections, err := h.SAMLConnUse.ListConnections(c.Request.Context(), "")
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve SAML connections", err))
		return
	}
	c.JSON(http.StatusOK, connections)
}

func (h *ManagementHandler) ListSAMLConnectionsByTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "tenant_id is required", nil))
		return
	}

	connections, err := h.SAMLConnUse.ListConnections(c.Request.Context(), tenantID)
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve SAML connections for tenant", err))
		return
	}
	c.JSON(http.StatusOK, connections)
}

func (h *ManagementHandler) GetSAMLConnection(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	id := c.Param("id")
	conn, err := h.SAMLConnUse.GetConnection(c.Request.Context(), tenantID, id)
	if err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "SAML Connection not found", err))
		return
	}
	c.JSON(http.StatusOK, conn)
}

func (h *ManagementHandler) UpdateSAMLConnection(c *gin.Context) {
	var req dto.CreateSAMLConnectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	updateData := entity.SAMLConnection{
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
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to update SAML connection", err))
		return
	}
	logger.FromGin(c).Info("SAML connection updated successfully", zap.String("entity_id", updateData.IdpEntityID), zap.String("target_tenant_id", updateData.TenantID), zap.String("protocol", "saml"))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *ManagementHandler) DeleteSAMLConnection(c *gin.Context) {
	id := c.Param("id")
	tenantID := c.Param("tenant_id")
	err := h.SAMLConnUse.DeleteConnection(c.Request.Context(), tenantID, id, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to delete SAML connection", err))
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// --- OIDC Connection Management ---

func (h *ManagementHandler) CreateOIDCConnection(c *gin.Context) {
	var conn dto.CreateOIDCConnectionRequest
	if err := c.ShouldBindJSON(&conn); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	realTenantID, ok := h.resolveTenantID(c, conn.TenantID)
	if !ok {
		return
	}
	conn.TenantID = realTenantID

	connection := &entity.OIDCConnection{
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
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to create OIDC connection", err))
		return
	}
	logger.FromGin(c).Info("OIDC connection created successfully", zap.String("client_id", savedConn.ClientID), zap.String("target_tenant_id", savedConn.TenantID), zap.String("protocol", "oidc"))
	c.JSON(http.StatusCreated, conn)
}

func (h *ManagementHandler) ListOIDCConnections(c *gin.Context) {
	connections, err := h.OIDCConnUse.ListConnections(c.Request.Context(), "")
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve OIDC connections", err))
		return
	}
	c.JSON(http.StatusOK, connections)
}

func (h *ManagementHandler) ListOIDCConnectionsByTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "tenant_id is required", nil))
		return
	}

	connections, err := h.OIDCConnUse.ListConnections(c.Request.Context(), tenantID)
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve OIDC connections for tenant", err))
		return
	}
	c.JSON(http.StatusOK, connections)
}

func (h *ManagementHandler) GetOIDCConnection(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	id := c.Param("id")
	connection, err := h.OIDCConnUse.GetConnection(c.Request.Context(), tenantID, id)
	if err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "OIDC Connection not found", err))
		return
	}
	c.JSON(http.StatusOK, connection)
}

func (h *ManagementHandler) UpdateOIDCConnection(c *gin.Context) {
	var req dto.CreateOIDCConnectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	updateData := entity.OIDCConnection{
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
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to update OIDC connection", err))
		return
	}
	logger.FromGin(c).Info("OIDC connection updated successfully", zap.String("client_id", updateData.ClientID), zap.String("target_tenant_id", updateData.TenantID), zap.String("protocol", "oidc"))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *ManagementHandler) DeleteOIDCConnection(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	id := c.Param("id")
	err := h.OIDCConnUse.DeleteConnection(c.Request.Context(), tenantID, id, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to delete OIDC connection", err))
		return
	}
	logger.FromGin(c).Info("OIDC connection deleted successfully", zap.String("client_id", id), zap.String("protocol", "oidc"))
	c.JSON(http.StatusNoContent, nil)
}
