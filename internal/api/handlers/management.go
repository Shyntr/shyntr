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

func (h *ManagementHandler) CreateClient(c *gin.Context) {
	var client models.OAuth2Client
	if err := c.ShouldBindJSON(&client); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
	tenantID := c.Query("tenant_id")
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

func (h *ManagementHandler) CreateSAMLConnection(c *gin.Context) {
	var conn models.SAMLConnection
	if err := c.ShouldBindJSON(&conn); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
	tenantID := c.Query("tenant_id")
	var conns []models.SAMLConnection
	if err := h.DB.Where("tenant_id = ?", tenantID).Find(&conns).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, conns)
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

	if err := h.DB.Create(&conn).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create oidc connection"})
		return
	}
	c.JSON(http.StatusCreated, conn)
}

func (h *ManagementHandler) ListOIDCConnections(c *gin.Context) {
	tenantID := c.Query("tenant_id")
	var conns []models.OIDCConnection
	if err := h.DB.Where("tenant_id = ?", tenantID).Find(&conns).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, conns)
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
