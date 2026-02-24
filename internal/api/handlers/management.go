package handlers

import (
	"encoding/xml"
	"fmt"
	"net/http"

	"github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/internal/api/response"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/crypto"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/ory/fosite"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type ManagementHandler struct {
	DB           *gorm.DB
	FositeConfig *fosite.Config
}

func NewManagementHandler(db *gorm.DB, fositeCfg *fosite.Config) *ManagementHandler {
	return &ManagementHandler{DB: db, FositeConfig: fositeCfg}
}

func (h *ManagementHandler) resolveTenantID(c *gin.Context, inputID string) (string, bool) {
	if inputID == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "Tenant ID is required", nil))
		return "", false
	}

	var tenant models.Tenant

	if err := h.DB.Select("id").First(&tenant, "id = ?", inputID).Error; err == nil {
		return tenant.ID, true
	}

	if err := h.DB.Select("id").First(&tenant, "name = ?", inputID).Error; err == nil {
		return tenant.ID, true
	}

	c.Error(response.NewAppError(http.StatusNotFound, "The specified tenant does not exist", nil))
	return "", false
}

func (h *ManagementHandler) GetDashboardStats(c *gin.Context) {
	tenantID := c.Query("tenant_id")

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

	applyFilter := func(db *gorm.DB) *gorm.DB {
		if tenantID != "" {
			return db.Where("tenant_id = ?", tenantID)
		}
		return db
	}

	applyFilter(h.DB.Model(&models.OAuth2Client{})).Count(&stats.TotalOIDCClients)
	applyFilter(h.DB.Model(&models.SAMLClient{})).Count(&stats.TotalSAMLClients)
	applyFilter(h.DB.Model(&models.SAMLConnection{})).Count(&stats.TotalSAMLConnections)
	applyFilter(h.DB.Model(&models.OIDCConnection{})).Count(&stats.TotalOIDCConnections)

	h.DB.Model(&models.Tenant{}).Count(&stats.TotalTenants)

	applyFilter(h.DB.Model(&models.OAuth2Client{}).Where("public = ?", true)).Count(&stats.PublicClients)
	applyFilter(h.DB.Model(&models.OAuth2Client{}).Where("public = ?", false)).Count(&stats.ConfidentialClients)

	var recentLogins []models.LoginRequest
	loginQuery := h.DB.Order("created_at desc").Limit(5)
	if tenantID != "" {
		loginQuery = loginQuery.Where("tenant_id = ?", tenantID)
	}
	loginQuery.Find(&recentLogins)

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
	var tenants []models.Tenant
	if err := h.DB.Find(&tenants).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve tenants", err))
		return
	}
	c.JSON(http.StatusOK, tenants)
}

func (h *ManagementHandler) GetTenant(c *gin.Context) {
	id := c.Param("id")
	var tenant models.Tenant
	if err := h.DB.First(&tenant, "id = ?", id).Error; err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "Tenant not found", err))
		return
	}
	c.JSON(http.StatusOK, tenant)
}

func (h *ManagementHandler) CreateTenant(c *gin.Context) {
	var tenant models.Tenant
	if err := c.ShouldBindJSON(&tenant); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}
	if err := h.DB.Create(&tenant).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to create tenant", err))
		return
	}
	logger.FromGin(c).Info("Tenant created successfully", zap.String("target_tenant_id", tenant.ID), zap.String("tenant_name", tenant.Name))
	c.JSON(http.StatusCreated, tenant)
}

func (h *ManagementHandler) UpdateTenant(c *gin.Context) {
	id := c.Param("id")
	var req models.Tenant
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	updates := map[string]interface{}{
		"name":         req.Name,
		"display_name": req.DisplayName,
		"description":  req.Description,
		"issuer_url":   req.IssuerURL,
	}

	if err := h.DB.Model(&models.Tenant{}).Where("id = ?", id).Updates(updates).Error; err != nil {
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

	err := h.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("tenant_id = ?", tenantID).Delete(&models.OAuth2Client{}).Error; err != nil {
			return fmt.Errorf("failed to delete oidc clients: %w", err)
		}
		if err := tx.Where("tenant_id = ?", tenantID).Delete(&models.SAMLClient{}).Error; err != nil {
			return fmt.Errorf("failed to delete saml clients: %w", err)
		}
		if err := tx.Where("tenant_id = ?", tenantID).Delete(&models.OIDCConnection{}).Error; err != nil {
			return fmt.Errorf("failed to delete oidc connections: %w", err)
		}
		if err := tx.Where("tenant_id = ?", tenantID).Delete(&models.SAMLConnection{}).Error; err != nil {
			return fmt.Errorf("failed to delete saml connections: %w", err)
		}
		if err := tx.Where("tenant_id = ?", tenantID).Delete(&models.LoginRequest{}).Error; err != nil {
			return fmt.Errorf("failed to delete login requests: %w", err)
		}
		if err := tx.Where("id = ?", tenantID).Delete(&models.Tenant{}).Error; err != nil {
			return fmt.Errorf("failed to delete tenant: %w", err)
		}
		return nil
	})

	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to cascade delete tenant", err))
		return
	}
	logger.FromGin(c).Info("Tenant deleted successfully", zap.String("target_tenant_id", tenantID))
	c.JSON(http.StatusOK, gin.H{"message": "Tenant and all associated resources deleted successfully"})
}

// --- OAuth2 Clients Management ---

func (h *ManagementHandler) CreateClient(c *gin.Context) {
	var client models.OAuth2Client
	if err := c.ShouldBindJSON(&client); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	realTenantID, ok := h.resolveTenantID(c, client.TenantID)
	if !ok {
		return
	}
	client.TenantID = realTenantID

	clientSecret := client.Secret
	if clientSecret != "" {
		hashedSecret, err := crypto.HashSecret(c.Request.Context(), h.FositeConfig, clientSecret)
		if err != nil {
			c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to hash client secret", err))
			return
		}
		client.Secret = hashedSecret
	}

	if err := h.DB.Create(&client).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to create OIDC client", err))
		return
	}
	logger.FromGin(c).Info("OIDC client created successfully", zap.String("client_id", client.ID), zap.String("target_tenant_id", client.TenantID), zap.String("protocol", "oidc"))
	c.JSON(http.StatusCreated, client)
}

func (h *ManagementHandler) ListClients(c *gin.Context) {
	var clients []models.OAuth2Client
	if err := h.DB.Find(&clients).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve clients", err))
		return
	}

	c.JSON(http.StatusOK, clients)
}

func (h *ManagementHandler) ListClientsByTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "tenant_id is required", nil))
		return
	}

	var clients []models.OAuth2Client
	if err := h.DB.Where("tenant_id = ?", tenantID).Find(&clients).Error; err != nil {
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
	var client models.OAuth2Client
	if err := h.DB.First(&client, "id = ?", id).Error; err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "OIDC Client not found", err))
		return
	}
	client.Secret = "*****"
	c.JSON(http.StatusOK, client)
}

func (h *ManagementHandler) UpdateClient(c *gin.Context) {
	id := c.Param("id")
	var req models.OAuth2Client
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	var client models.OAuth2Client
	if err := h.DB.First(&client, "id = ?", id).Error; err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "OIDC Client not found", err))
		return
	}

	updates := map[string]interface{}{
		"name":                       req.Name,
		"redirect_uris":              req.RedirectURIs,
		"scopes":                     req.Scopes,
		"grant_types":                req.GrantTypes,
		"response_types":             req.ResponseTypes,
		"public":                     req.Public,
		"token_endpoint_auth_method": req.TokenEndpointAuthMethod,
		"enforce_pkce":               req.EnforcePKCE,
		"allowed_cors_origins":       req.AllowedCORSOrigins,
		"audience":                   req.Audience,
		"post_logout_redirect_uris":  req.PostLogoutRedirectURIs,
		"access_token_lifespan":      req.AccessTokenLifespan,
		"id_token_lifespan":          req.IDTokenLifespan,
		"refresh_token_lifespan":     req.RefreshTokenLifespan,
	}

	if req.Secret != "" && req.Secret != "*****" {
		hashed, _ := crypto.HashSecret(c.Request.Context(), h.FositeConfig, req.Secret)
		updates["secret"] = hashed
	}

	if err := h.DB.Model(&client).Updates(updates).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to update OIDC client", err))
		return
	}
	logger.FromGin(c).Info("OIDC client updated successfully", zap.String("client_id", id), zap.String("protocol", "oidc"))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *ManagementHandler) DeleteClient(c *gin.Context) {
	id := c.Param("id")
	if err := h.DB.Delete(&models.OAuth2Client{}, "id = ?", id).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to delete OIDC client", err))
		return
	}
	logger.FromGin(c).Info("OIDC client deleted successfully", zap.String("client_id", id), zap.String("protocol", "oidc"))
	c.JSON(http.StatusNoContent, nil)
}

func (h *ManagementHandler) ListSAMLClients(c *gin.Context) {
	var clients []models.SAMLClient
	if err := h.DB.Find(&clients).Error; err != nil {
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

	var clients []models.SAMLClient
	if err := h.DB.Where("tenant_id = ?", tenantID).Find(&clients).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve SAML clients for tenant", err))
		return
	}
	c.JSON(http.StatusOK, clients)
}

func (h *ManagementHandler) GetSAMLClient(c *gin.Context) {
	id := c.Param("id")
	var client models.SAMLClient
	if err := h.DB.First(&client, "id = ?", id).Error; err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "SAML Client not found", err))
		return
	}
	c.JSON(http.StatusOK, client)
}

func (h *ManagementHandler) CreateSAMLClient(c *gin.Context) {
	var client models.SAMLClient
	if err := c.ShouldBindJSON(&client); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	realTenantID, ok := h.resolveTenantID(c, client.TenantID)
	if !ok {
		return
	}
	client.TenantID = realTenantID

	if err := h.DB.Create(&client).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to create SAML client", err))
		return
	}
	logger.FromGin(c).Info("SAML client created successfully", zap.String("client_id", client.ID), zap.String("target_tenant_id", client.TenantID), zap.String("protocol", "saml"))
	c.JSON(http.StatusCreated, client)
}

func (h *ManagementHandler) UpdateSAMLClient(c *gin.Context) {
	id := c.Param("id")
	var req models.SAMLClient
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	result := h.DB.Model(&models.SAMLClient{}).
		Where("id = ?", id).
		Select(
			"Name", "EntityID", "ACSURL", "SPCertificate",
			"AttributeMapping", "ForceAuthn", "SignResponse",
			"SignAssertion", "EncryptAssertion", "Active", "TenantID",
		).
		Updates(models.SAMLClient{
			Name:             req.Name,
			EntityID:         req.EntityID,
			TenantID:         req.TenantID,
			ACSURL:           req.ACSURL,
			SPCertificate:    req.SPCertificate,
			AttributeMapping: req.AttributeMapping,
			ForceAuthn:       req.ForceAuthn,
			SignResponse:     req.SignResponse,
			SignAssertion:    req.SignAssertion,
			EncryptAssertion: req.EncryptAssertion,
			Active:           req.Active,
		})

	if result.Error != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to update SAML client", result.Error))
		return
	}
	logger.FromGin(c).Info("SAML client created successfully", zap.String("entity_id", req.EntityID), zap.String("target_tenant_id", req.TenantID), zap.String("protocol", "saml"))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *ManagementHandler) DeleteSAMLClient(c *gin.Context) {
	id := c.Param("id")
	if err := h.DB.Delete(&models.SAMLClient{}, "id = ?", id).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to delete SAML client", err))
		return
	}
	logger.FromGin(c).Info("SAML client deleted successfully", zap.String("client_id", id), zap.String("protocol", "saml"))
	c.JSON(http.StatusNoContent, nil)
}

// --- SAML Connection Management (Identity Providers) ---

func (h *ManagementHandler) CreateSAMLConnection(c *gin.Context) {
	var conn models.SAMLConnection
	if err := c.ShouldBindJSON(&conn); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	realTenantID, ok := h.resolveTenantID(c, conn.TenantID)
	if !ok {
		return
	}
	conn.TenantID = realTenantID

	if conn.IdpMetadataXML != "" {
		meta := &saml.EntityDescriptor{}
		if err := xml.Unmarshal([]byte(conn.IdpMetadataXML), meta); err != nil {
			c.Error(response.NewAppError(http.StatusBadRequest, "Invalid SAML IdP metadata XML", err))
			return
		}
		conn.IdpEntityID = meta.EntityID
	} else {
		c.Error(response.NewAppError(http.StatusBadRequest, "idp_metadata_xml is required", nil))
		return
	}

	if err := h.DB.Create(&conn).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to create SAML connection", err))
		return
	}
	logger.FromGin(c).Info("SAML connection created successfully", zap.String("entity_id", conn.IdpEntityID), zap.String("target_tenant_id", conn.TenantID), zap.String("protocol", "saml"))
	c.JSON(http.StatusCreated, conn)
}

func (h *ManagementHandler) ListSAMLConnections(c *gin.Context) {
	var conns []models.SAMLConnection
	if err := h.DB.Find(&conns).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve SAML connections", err))
		return
	}
	c.JSON(http.StatusOK, conns)
}

func (h *ManagementHandler) ListSAMLConnectionsByTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "tenant_id is required", nil))
		return
	}

	var conns []models.SAMLConnection
	if err := h.DB.Where("tenant_id = ?", tenantID).Find(&conns).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve SAML connections for tenant", err))
		return
	}
	c.JSON(http.StatusOK, conns)
}

func (h *ManagementHandler) GetSAMLConnection(c *gin.Context) {
	id := c.Param("id")
	var conn models.SAMLConnection
	if err := h.DB.First(&conn, "id = ?", id).Error; err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "SAML Connection not found", err))
		return
	}
	c.JSON(http.StatusOK, conn)
}

func (h *ManagementHandler) UpdateSAMLConnection(c *gin.Context) {
	id := c.Param("id")
	var req models.SAMLConnection
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	updateData := models.SAMLConnection{
		Name:             req.Name,
		TenantID:         req.TenantID,
		AttributeMapping: req.AttributeMapping,
		ForceAuthn:       req.ForceAuthn,
		SignRequest:      req.SignRequest,
		Active:           req.Active,
		SPPrivateKey:     req.SPPrivateKey,
		SPCertificate:    req.SPCertificate,
	}

	if req.IdpMetadataXML != "" {
		meta := &saml.EntityDescriptor{}
		if err := xml.Unmarshal([]byte(req.IdpMetadataXML), meta); err != nil {
			c.Error(response.NewAppError(http.StatusBadRequest, "Invalid SAML IdP metadata XML", err))
			return
		}
		updateData.IdpMetadataXML = req.IdpMetadataXML
		updateData.IdpEntityID = meta.EntityID
	}

	result := h.DB.Model(&models.SAMLConnection{}).Where("id = ?", id).Updates(updateData)

	if result.Error != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to update SAML connection", result.Error))
		return
	}
	if result.RowsAffected == 0 {
		c.Error(response.NewAppError(http.StatusNotFound, "SAML Connection not found", nil))
		return
	}
	logger.FromGin(c).Info("SAML connection updated successfully", zap.String("entity_id", updateData.IdpEntityID), zap.String("target_tenant_id", updateData.TenantID), zap.String("protocol", "saml"))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *ManagementHandler) DeleteSAMLConnection(c *gin.Context) {
	id := c.Param("id")
	if err := h.DB.Delete(&models.SAMLConnection{}, "id = ?", id).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to delete SAML connection", err))
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// --- OIDC Connection Management ---

func (h *ManagementHandler) CreateOIDCConnection(c *gin.Context) {
	var conn models.OIDCConnection
	if err := c.ShouldBindJSON(&conn); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	realTenantID, ok := h.resolveTenantID(c, conn.TenantID)
	if !ok {
		return
	}
	conn.TenantID = realTenantID

	if err := h.DB.Create(&conn).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to create OIDC connection", err))
		return
	}
	logger.FromGin(c).Info("OIDC connection created successfully", zap.String("client_id", conn.ClientID), zap.String("target_tenant_id", conn.TenantID), zap.String("protocol", "oidc"))
	c.JSON(http.StatusCreated, conn)
}

func (h *ManagementHandler) ListOIDCConnections(c *gin.Context) {
	var conns []models.OIDCConnection
	if err := h.DB.Find(&conns).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve OIDC connections", err))
		return
	}
	c.JSON(http.StatusOK, conns)
}

func (h *ManagementHandler) ListOIDCConnectionsByTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "tenant_id is required", nil))
		return
	}

	var conns []models.OIDCConnection
	if err := h.DB.Where("tenant_id = ?", tenantID).Find(&conns).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve OIDC connections for tenant", err))
		return
	}
	c.JSON(http.StatusOK, conns)
}

func (h *ManagementHandler) GetOIDCConnection(c *gin.Context) {
	id := c.Param("id")
	var conn models.OIDCConnection
	if err := h.DB.First(&conn, "id = ?", id).Error; err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "OIDC Connection not found", err))
		return
	}
	c.JSON(http.StatusOK, conn)
}

func (h *ManagementHandler) UpdateOIDCConnection(c *gin.Context) {
	id := c.Param("id")
	var req models.OIDCConnection
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	updateData := models.OIDCConnection{
		Name:                  req.Name,
		TenantID:              req.TenantID,
		IssuerURL:             req.IssuerURL,
		ClientID:              req.ClientID,
		ClientSecret:          req.ClientSecret,
		AuthorizationEndpoint: req.AuthorizationEndpoint,
		TokenEndpoint:         req.TokenEndpoint,
		UserInfoEndpoint:      req.UserInfoEndpoint,
		JWKSURI:               req.JWKSURI,
		Scopes:                req.Scopes,
		AttributeMapping:      req.AttributeMapping,
		Active:                req.Active,
	}

	result := h.DB.Model(&models.OIDCConnection{}).Where("id = ?", id).Updates(updateData)

	if result.Error != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to update OIDC connection", result.Error))
		return
	}
	if result.RowsAffected == 0 {
		c.Error(response.NewAppError(http.StatusNotFound, "OIDC Connection not found", nil))
		return
	}
	logger.FromGin(c).Info("OIDC connection created successfully", zap.String("client_id", updateData.ClientID), zap.String("target_tenant_id", updateData.TenantID), zap.String("protocol", "oidc"))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *ManagementHandler) DeleteOIDCConnection(c *gin.Context) {
	id := c.Param("id")
	if err := h.DB.Delete(&models.OIDCConnection{}, "id = ?", id).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to delete OIDC connection", err))
		return
	}
	logger.FromGin(c).Info("OIDC connection created successfully", zap.String("client_id", id), zap.String("protocol", "oidc"))
	c.JSON(http.StatusNoContent, nil)
}
