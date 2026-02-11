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

	sp, err := h.Service.GetServiceProvider(c.Request.Context(), tenantID)
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

	redirectURL, err := h.Service.InitiateSSO(c.Request.Context(), tenantID, connectionID, loginChallenge)
	if err != nil {
		logger.Log.Error("Failed to initiate SAML SSO", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sso_init_failed", "details": err.Error()})
		return
	}

	c.Redirect(http.StatusFound, redirectURL)
}

func (h *SAMLHandler) ACS(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Service.Config.DefaultTenantID
	}

	assertion, relayState, err := h.Service.HandleACS(c.Request.Context(), tenantID, c.Request)
	if err != nil {
		logger.Log.Warn("SAML ACS Validation Failed", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid_saml_response", "details": err.Error()})
		return
	}

	loginChallenge := relayState
	if loginChallenge == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing_relay_state"})
		return
	}

	subject := assertion.Subject.NameID.Value
	attributes := make(map[string]interface{})

	for _, statement := range assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			// Attribute değerlerini al
			if len(attr.Values) > 1 {
				vals := make([]string, len(attr.Values))
				for i, v := range attr.Values {
					vals[i] = v.Value
				}
				attributes[attr.Name] = vals
			} else if len(attr.Values) == 1 {
				attributes[attr.Name] = attr.Values[0].Value
			}
		}
	}

	attributes["email"] = subject
	attributes["source"] = "saml"

	var req models.LoginRequest
	if err := h.DB.First(&req, "id = ?", loginChallenge).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "login_request_expired"})
		return
	}

	contextBytes, _ := json.Marshal(attributes)
	req.Authenticated = true
	req.Subject = subject
	req.Context = contextBytes
	req.UpdatedAt = time.Now()

	if err := h.DB.Save(&req).Error; err != nil {
		logger.Log.Error("Failed to update login request", zap.Error(err))
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	redirectURL := fmt.Sprintf("%s&login_verifier=%s", req.RequestURL, req.ID)
	c.Redirect(http.StatusFound, redirectURL)
}
