package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/internal/core/oidc"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type OIDCHandler struct {
	Service *oidc.ClientService
	DB      *gorm.DB
}

func NewOIDCHandler(s *oidc.ClientService, db *gorm.DB) *OIDCHandler {
	return &OIDCHandler{Service: s, DB: db}
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
		logger.Log.Error("Failed to initiate OIDC", zap.Error(err))
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

	parts := strings.Split(state, "|")
	if len(parts) != 2 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_state_format"})
		return
	}
	loginChallenge := parts[0]
	connectionID := parts[1]

	var loginReq models.LoginRequest
	if err := h.DB.First(&loginReq, "id = ?", loginChallenge).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "session_expired"})
		return
	}

	userInfo, err := h.Service.ExchangeAndUserInfo(c.Request.Context(), tenantID, code, connectionID)
	if err != nil {
		logger.Log.Error("OIDC Exchange Failed", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "token_exchange_failed", "details": err.Error()})
		return
	}

	// TODO: Connection üzerindeki AttributeMapping kurallarını uygula.
	finalAttributes := userInfo
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
	c.Redirect(http.StatusFound, redirectURL)
}
