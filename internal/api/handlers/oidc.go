package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/internal/core/mapper"
	"github.com/nevzatcirak/shyntr/internal/core/oidc"
	"github.com/nevzatcirak/shyntr/internal/core/webhook"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type OIDCHandler struct {
	Service        *oidc.ClientService
	Mapper         *mapper.Mapper
	DB             *gorm.DB
	WebhookService *webhook.Service
}

func NewOIDCHandler(s *oidc.ClientService, m *mapper.Mapper, db *gorm.DB, wh *webhook.Service) *OIDCHandler {
	return &OIDCHandler{Service: s, Mapper: m, DB: db, WebhookService: wh}
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
	finalAttributes["idp"] = fmt.Sprintf("oidc:%s", connectionID)
	finalAttributes["amr"] = []string{"ext"}
	if _, ok := finalAttributes["sub"]; !ok {
		finalAttributes["sub"] = subject
	}
	h.WebhookService.FireEvent(tenantID, "user.login.ext", finalAttributes)

	loginReq.Authenticated = true
	loginReq.Subject = subject
	loginReq.UpdatedAt = time.Now()

	var existingCtx map[string]interface{}
	if len(loginReq.Context) > 0 {
		_ = json.Unmarshal(loginReq.Context, &existingCtx)
	} else {
		existingCtx = make(map[string]interface{})
	}

	existingCtx["login_claims"] = finalAttributes
	mergedBytes, _ := json.Marshal(existingCtx)
	loginReq.Context = mergedBytes
	if err := h.DB.Save(&loginReq).Error; err != nil {
		logger.FromGin(c).Error("Failed to update login request", zap.Error(err), zap.String("protocol", "oidc"))
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	var redirectTo string

	if loginReq.Protocol == "saml" {
		redirectTo = fmt.Sprintf("%s/t/%s/saml/resume?login_challenge=%s",
			strings.TrimSuffix(h.Service.Config.BaseIssuerURL, "/"),
			tenantID,
			loginReq.ID,
		)
	} else {
		redirectPath := loginReq.RequestURL
		if !strings.HasPrefix(redirectPath, "http") {
			base := strings.TrimSuffix(h.Service.Config.BaseIssuerURL, "/")
			if !strings.HasPrefix(redirectPath, "/") {
				redirectPath = "/" + redirectPath
			}
			redirectPath = base + redirectPath
		}
		if strings.Contains(redirectPath, "?") {
			redirectTo = fmt.Sprintf("%s&login_verifier=%s", redirectPath, loginReq.ID)
		} else {
			redirectTo = fmt.Sprintf("%s?login_verifier=%s", redirectPath, loginReq.ID)
		}
	}

	c.Redirect(http.StatusFound, redirectTo)
}
