package handlers

import (
	"encoding/xml"
	"net/http"

	"github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/crypto"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type ManagementHandler struct {
	DB *gorm.DB
}

func NewManagementHandler(db *gorm.DB) *ManagementHandler {
	return &ManagementHandler{DB: db}
}

func (h *ManagementHandler) checkTenantExists(c *gin.Context, tenantID string) bool {
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id_required"})
		return false
	}

	var count int64
	if err := h.DB.Model(&models.Tenant{}).Where("id = ?", tenantID).Count(&count).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database_error"})
		return false
	}

	if count == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant_not_found", "message": "The specified tenant does not exist."})
		return false
	}

	return true
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
			"id":        l.ID,
			"subject":   l.Subject,
			"client_id": l.ClientID,
			"status":    status,
			"timestamp": l.CreatedAt,
		}
		stats.RecentActivity = append(stats.RecentActivity, activity)
	}

	c.JSON(http.StatusOK, stats)
}

func (h *ManagementHandler) ListTenants(c *gin.Context) {
	var tenants []models.Tenant
	if err := h.DB.Find(&tenants).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, tenants)
}

func (h *ManagementHandler) GetTenant(c *gin.Context) {
	id := c.Param("id")
	var tenant models.Tenant
	if err := h.DB.First(&tenant, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		return
	}
	c.JSON(http.StatusOK, tenant)
}

func (h *ManagementHandler) CreateTenant(c *gin.Context) {
	var tenant models.Tenant
	if err := c.ShouldBindJSON(&tenant); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.DB.Create(&tenant).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create tenant"})
		return
	}
	c.JSON(http.StatusCreated, tenant)
}

func (h *ManagementHandler) UpdateTenant(c *gin.Context) {
	id := c.Param("id")
	var req models.Tenant
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := map[string]interface{}{
		"name":         req.Name,
		"display_name": req.DisplayName,
		"description":  req.Description,
		"issuer_url":   req.IssuerURL,
	}

	if err := h.DB.Model(&models.Tenant{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *ManagementHandler) DeleteTenant(c *gin.Context) {
	id := c.Param("id")
	if id == "default" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete default tenant"})
		return
	}
	if err := h.DB.Delete(&models.Tenant{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// --- OAuth2 Clients Management ---

func (h *ManagementHandler) CreateClient(c *gin.Context) {
	var client models.OAuth2Client
	if err := c.ShouldBindJSON(&client); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !h.checkTenantExists(c, client.TenantID) {
		return
	}

	if client.Secret != "" {
		hashed, err := crypto.HashPassword(client.Secret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash secret"})
			return
		}
		client.Secret = hashed
	}

	if err := h.DB.Create(&client).Error; err != nil {
		logger.Log.Error("Failed to create client", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create client"})
		return
	}

	c.JSON(http.StatusCreated, client)
}

func (h *ManagementHandler) ListClients(c *gin.Context) {
	var clients []models.OAuth2Client
	if err := h.DB.Find(&clients).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	c.JSON(http.StatusOK, clients)
}

func (h *ManagementHandler) ListClientsByTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
		return
	}

	var clients []models.OAuth2Client
	if err := h.DB.Where("tenant_id = ?", tenantID).Find(&clients).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
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
		c.JSON(http.StatusNotFound, gin.H{"error": "client not found"})
		return
	}
	client.Secret = "*****"
	c.JSON(http.StatusOK, client)
}

func (h *ManagementHandler) UpdateClient(c *gin.Context) {
	id := c.Param("id")
	var req models.OAuth2Client
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var client models.OAuth2Client
	if err := h.DB.First(&client, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "client not found"})
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
		hashed, _ := crypto.HashPassword(req.Secret)
		updates["secret"] = hashed
	}

	if err := h.DB.Model(&client).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *ManagementHandler) DeleteClient(c *gin.Context) {
	id := c.Param("id")
	if err := h.DB.Delete(&models.OAuth2Client{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

func (h *ManagementHandler) ListSAMLClients(c *gin.Context) {
	var clients []models.SAMLClient
	if err := h.DB.Find(&clients).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, clients)
}

func (h *ManagementHandler) ListSAMLClientsByTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
		return
	}

	var clients []models.SAMLClient
	if err := h.DB.Where("tenant_id = ?", tenantID).Find(&clients).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, clients)
}

func (h *ManagementHandler) GetSAMLClient(c *gin.Context) {
	id := c.Param("id")
	var client models.SAMLClient
	if err := h.DB.First(&client, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "saml client not found"})
		return
	}
	c.JSON(http.StatusOK, client)
}

func (h *ManagementHandler) CreateSAMLClient(c *gin.Context) {
	var client models.SAMLClient
	if err := c.ShouldBindJSON(&client); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !h.checkTenantExists(c, client.TenantID) {
		return
	}

	if err := h.DB.Create(&client).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create saml client"})
		return
	}
	c.JSON(http.StatusCreated, client)
}

func (h *ManagementHandler) UpdateSAMLClient(c *gin.Context) {
	id := c.Param("id")
	var req models.SAMLClient
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := map[string]interface{}{
		"name":              req.Name,
		"entity_id":         req.EntityID,
		"acs_url":           req.ACSURL,
		"sp_certificate":    req.SPCertificate,
		"attribute_mapping": req.AttributeMapping,
		"force_authn":       req.ForceAuthn,
		"sign_response":     req.SignResponse,
		"sign_assertion":    req.SignAssertion,
		"encrypt_assertion": req.EncryptAssertion,
		"active":            req.Active,
	}

	if err := h.DB.Model(&models.SAMLClient{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *ManagementHandler) DeleteSAMLClient(c *gin.Context) {
	id := c.Param("id")
	if err := h.DB.Delete(&models.SAMLClient{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// --- SAML Connection Management (Identity Providers) ---

func (h *ManagementHandler) CreateSAMLConnection(c *gin.Context) {
	var conn models.SAMLConnection
	if err := c.ShouldBindJSON(&conn); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !h.checkTenantExists(c, conn.TenantID) {
		return
	}

	if conn.IdpMetadataXML != "" {
		meta := &saml.EntityDescriptor{}
		if err := xml.Unmarshal([]byte(conn.IdpMetadataXML), meta); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_metadata_xml", "details": err.Error()})
			return
		}
		conn.IdpEntityID = meta.EntityID
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "idp_metadata_xml_required"})
		return
	}

	if err := h.DB.Create(&conn).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create saml connection"})
		return
	}
	c.JSON(http.StatusCreated, conn)
}

func (h *ManagementHandler) ListSAMLConnections(c *gin.Context) {
	var conns []models.SAMLConnection
	if err := h.DB.Find(&conns).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, conns)
}

func (h *ManagementHandler) ListSAMLConnectionsByTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
		return
	}

	var conns []models.SAMLConnection
	if err := h.DB.Where("tenant_id = ?", tenantID).Find(&conns).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, conns)
}

func (h *ManagementHandler) GetSAMLConnection(c *gin.Context) {
	id := c.Param("id")
	var conn models.SAMLConnection
	if err := h.DB.First(&conn, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "connection not found"})
		return
	}
	c.JSON(http.StatusOK, conn)
}

func (h *ManagementHandler) UpdateSAMLConnection(c *gin.Context) {
	id := c.Param("id")
	var req models.SAMLConnection
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := map[string]interface{}{
		"name":              req.Name,
		"attribute_mapping": req.AttributeMapping,
		"force_authn":       req.ForceAuthn,
		"sign_request":      req.SignRequest,
		"active":            req.Active,
		"sp_private_key":    req.SPPrivateKey,
		"sp_certificate":    req.SPCertificate,
	}

	if req.IdpMetadataXML != "" {
		meta := &saml.EntityDescriptor{}
		if err := xml.Unmarshal([]byte(req.IdpMetadataXML), meta); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_metadata_xml", "details": err.Error()})
			return
		}
		updates["idp_metadata_xml"] = req.IdpMetadataXML
		updates["idp_entity_id"] = meta.EntityID
	}

	result := h.DB.Model(&models.SAMLConnection{}).Where("id = ?", id).Updates(updates)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "connection not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *ManagementHandler) DeleteSAMLConnection(c *gin.Context) {
	id := c.Param("id")
	if err := h.DB.Delete(&models.SAMLConnection{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// --- OIDC Connection Management ---

func (h *ManagementHandler) CreateOIDCConnection(c *gin.Context) {
	var conn models.OIDCConnection
	if err := c.ShouldBindJSON(&conn); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !h.checkTenantExists(c, conn.TenantID) {
		return
	}

	if err := h.DB.Create(&conn).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create oidc connection"})
		return
	}
	c.JSON(http.StatusCreated, conn)
}

func (h *ManagementHandler) ListOIDCConnections(c *gin.Context) {
	var conns []models.OIDCConnection
	if err := h.DB.Find(&conns).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, conns)
}

func (h *ManagementHandler) ListOIDCConnectionsByTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
		return
	}

	var conns []models.OIDCConnection
	if err := h.DB.Where("tenant_id = ?", tenantID).Find(&conns).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, conns)
}

func (h *ManagementHandler) GetOIDCConnection(c *gin.Context) {
	id := c.Param("id")
	var conn models.OIDCConnection
	if err := h.DB.First(&conn, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "connection not found"})
		return
	}
	c.JSON(http.StatusOK, conn)
}

func (h *ManagementHandler) UpdateOIDCConnection(c *gin.Context) {
	id := c.Param("id")
	var req models.OIDCConnection
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := map[string]interface{}{
		"name":                   req.Name,
		"issuer_url":             req.IssuerURL,
		"client_id":              req.ClientID,
		"client_secret":          req.ClientSecret,
		"authorization_endpoint": req.AuthorizationEndpoint,
		"token_endpoint":         req.TokenEndpoint,
		"user_info_endpoint":     req.UserInfoEndpoint,
		"jwks_uri":               req.JWKSURI,
		"scopes":                 req.Scopes,
		"attribute_mapping":      req.AttributeMapping,
		"active":                 req.Active,
	}

	result := h.DB.Model(&models.OIDCConnection{}).Where("id = ?", id).Updates(updates)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "connection not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *ManagementHandler) DeleteOIDCConnection(c *gin.Context) {
	id := c.Param("id")
	if err := h.DB.Delete(&models.OIDCConnection{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}
