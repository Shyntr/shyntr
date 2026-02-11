package handlers

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/internal/core/saml"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type SAMLHandler struct {
	Service *saml.Service
	DB      *gorm.DB
}

func NewSAMLHandler(s *saml.Service, db *gorm.DB) *SAMLHandler {
	return &SAMLHandler{Service: s, DB: db}
}

func (h *SAMLHandler) SPMetadata(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Service.Config.DefaultTenantID
	}

	sp, err := h.Service.BuildServiceProvider(c.Request.Context(), tenantID, nil)
	if err != nil {
		logger.Log.Error("Failed to initialize SP", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "saml_initialization_failed"})
		return
	}

	metaDesc := sp.Metadata()

	c.Header("Content-Type", "application/xml")
	if err := xml.NewEncoder(c.Writer).Encode(metaDesc); err != nil {
		logger.Log.Error("Failed to write metadata XML", zap.Error(err))
	}
}

func (h *SAMLHandler) IDPMetadata(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Shyntr currently operates as a SAML Service Provider only. IdP features are coming soon.",
	})
}

// Login initiates the SAML flow to a specific IDP Connection.
func (h *SAMLHandler) Login(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Service.Config.DefaultTenantID
	}
	connectionID := c.Param("connection_id")
	loginChallenge := c.Query("login_challenge")

	if loginChallenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_login_challenge"})
		return
	}

	var loginReq models.LoginRequest
	if err := h.DB.First(&loginReq, "id = ?", loginChallenge).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "login_request_not_found"})
		return
	}

	redirectURL, requestID, err := h.Service.InitiateSSO(c.Request.Context(), tenantID, connectionID, loginChallenge)
	if err != nil {
		logger.Log.Error("Failed to initiate SAML SSO", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sso_init_failed", "details": err.Error()})
		return
	}

	if requestID != "" {
		loginReq.SAMLRequestID = requestID
		h.DB.Save(&loginReq)
	}

	c.Redirect(http.StatusFound, redirectURL)
}

func (h *SAMLHandler) ACS(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Service.Config.DefaultTenantID
	}

	relayState := c.PostForm("RelayState")
	if relayState == "" {
		logger.Log.Warn("Missing RelayState in SAML Response")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing_relay_state"})
		return
	}

	var loginReq models.LoginRequest
	if err := h.DB.First(&loginReq, "id = ?", relayState).Error; err != nil {
		logger.Log.Warn("Invalid RelayState (LoginRequest not found)", zap.String("challenge", relayState))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid_session"})
		return
	}

	assertion, _, err := h.Service.HandleACS(c.Request.Context(), tenantID, c.Request, loginReq.SAMLRequestID)
	if err != nil {
		logger.Log.Warn("SAML ACS Validation Failed", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid_saml_response", "details": err.Error()})
		return
	}

	rawAttributes := make(map[string]interface{})
	for _, statement := range assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			if len(attr.Values) > 1 {
				vals := make([]string, len(attr.Values))
				for i, v := range attr.Values {
					vals[i] = v.Value
				}
				rawAttributes[attr.Name] = vals
			} else if len(attr.Values) == 1 {
				rawAttributes[attr.Name] = attr.Values[0].Value
			}
		}
	}

	issuer := assertion.Issuer.Value
	var conn models.SAMLConnection
	if err := h.DB.Select("attribute_mapping").Where("tenant_id = ? AND idp_entity_id = ?", tenantID, issuer).First(&conn).Error; err != nil {
		logger.Log.Warn("Connection not found for mapping, using raw attributes", zap.String("issuer", issuer))
	}

	finalAttributes := make(map[string]interface{})
	mapping := make(map[string]string)

	if len(conn.AttributeMapping) > 0 {
		_ = json.Unmarshal(conn.AttributeMapping, &mapping)
	}

	for oidcKey, samlKey := range mapping {
		if val, ok := rawAttributes[samlKey]; ok {
			finalAttributes[oidcKey] = val
		}
	}

	if len(finalAttributes) == 0 {
		finalAttributes = rawAttributes
	}

	subject := assertion.Subject.NameID.Value
	finalAttributes["email"] = subject
	finalAttributes["sub"] = subject
	finalAttributes["source"] = "saml"
	finalAttributes["issuer"] = issuer

	contextBytes, _ := json.Marshal(finalAttributes)
	loginReq.Authenticated = true
	loginReq.Subject = subject
	loginReq.Context = contextBytes
	loginReq.UpdatedAt = time.Now()

	if err := h.DB.Save(&loginReq).Error; err != nil {
		logger.Log.Error("Failed to update login request", zap.Error(err))
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	redirectURL := fmt.Sprintf("%s&login_verifier=%s", loginReq.RequestURL, loginReq.ID)
	c.Redirect(http.StatusFound, redirectURL)
}
