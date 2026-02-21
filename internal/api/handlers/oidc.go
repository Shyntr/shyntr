package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/internal/core/mapper"
	"github.com/nevzatcirak/shyntr/internal/core/oidc"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type OIDCHandler struct {
	Service *oidc.ClientService
	Mapper  *mapper.Mapper
	DB      *gorm.DB
}

func NewOIDCHandler(s *oidc.ClientService, m *mapper.Mapper, db *gorm.DB) *OIDCHandler {
	return &OIDCHandler{Service: s, Mapper: m, DB: db}
}

func (h *OIDCHandler) Login(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
		return
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

	redirectURL, err := h.Service.InitiateAuth(c.Request.Context(), tenantID, connectionID, loginChallenge)
	if err != nil {
		logger.FromGin(c).Error("Failed to initiate OIDC", zap.Error(err), zap.String("protocol", "oidc"))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "oidc_init_failed", "details": err.Error()})
		return
	}

	c.Redirect(http.StatusFound, redirectURL)
}

func (h *OIDCHandler) Callback(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_callback_params"})
		return
	}

	loginChallenge, connectionID, err := h.Service.VerifyState(state)
	if err != nil {
		logger.FromGin(c).Warn("Invalid OIDC state", zap.Error(err), zap.String("protocol", "oidc"))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid_state_token"})
		return
	}

	var loginReq models.LoginRequest
	if err := h.DB.First(&loginReq, "id = ?", loginChallenge).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "session_expired"})
		return
	}

	userInfo, err := h.Service.ExchangeAndUserInfo(c.Request.Context(), tenantID, code, connectionID)
	if err != nil {
		logger.FromGin(c).Error("OIDC Exchange Failed", zap.Error(err), zap.String("protocol", "oidc"))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "token_exchange_failed", "details": err.Error()})
		return
	}

	var conn models.OIDCConnection
	if err := h.DB.Select("attribute_mapping").First(&conn, "id = ?", connectionID).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "connection_not_found"})
		return
	}

	finalAttributes, err := h.Mapper.Map(userInfo, conn.AttributeMapping)
	if err != nil {
		logger.FromGin(c).Warn("Attribute mapping failed, falling back to raw", zap.Error(err), zap.String("protocol", "oidc"))
		finalAttributes = userInfo
	}

	subject, _ := userInfo["sub"].(string)
	if subject == "" {
		if id, ok := userInfo["id"].(string); ok {
			subject = id
		}
	}

	if email, ok := userInfo["email"].(string); ok && subject == "" {
		subject = email
	}

	finalAttributes["source"] = "oidc"
	finalAttributes["connection_id"] = connectionID
	if _, ok := finalAttributes["sub"]; !ok {
		finalAttributes["sub"] = subject
	}

	contextBytes, _ := json.Marshal(finalAttributes)
	loginReq.Authenticated = true
	loginReq.Subject = subject
	loginReq.Context = contextBytes
	loginReq.UpdatedAt = time.Now()

	if err := h.DB.Save(&loginReq).Error; err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	redirectURL := fmt.Sprintf("%s&login_verifier=%s", loginReq.RequestURL, loginReq.ID)
	logger.FromGin(c).Info("OIDC SSO callback processed successfully", zap.String("user_sub", subject), zap.String("protocol", "oidc"))
	c.Redirect(http.StatusFound, redirectURL)
}
