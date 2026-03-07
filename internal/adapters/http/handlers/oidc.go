package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/application/mapper"
	"github.com/nevzatcirak/shyntr/internal/application/port"
	"github.com/nevzatcirak/shyntr/internal/application/usecase"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
)

type OIDCHandler struct {
	Config        *config.Config
	clientUseCase usecase.OAuth2ClientUseCase
	AuthUse       usecase.AuthUseCase
	OIDCUse       usecase.OIDCConnectionUseCase
	Mapper        *mapper.Mapper
	AuditLogger   port.AuditLogger

	wh usecase.WebhookUseCase
}

func NewOIDCHandler(Config *config.Config, clientUseCase usecase.OAuth2ClientUseCase, AuthUse usecase.AuthUseCase,
	OIDCUse usecase.OIDCConnectionUseCase, m *mapper.Mapper, AuditLogger port.AuditLogger, wh usecase.WebhookUseCase) *OIDCHandler {
	return &OIDCHandler{Config: Config, clientUseCase: clientUseCase, AuthUse: AuthUse, OIDCUse: OIDCUse, Mapper: m, AuditLogger: AuditLogger, wh: wh}
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

	_, err := h.AuthUse.GetLoginRequest(c, loginChallenge)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "login_request_not_found"})
		return
	}

	redirectURL, err := h.clientUseCase.InitiateAuth(c.Request.Context(), tenantID, connectionID, loginChallenge)
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

	loginChallenge, connectionID, err := h.clientUseCase.VerifyState(state)
	if err != nil {
		logger.FromGin(c).Warn("Invalid OIDC state", zap.Error(err), zap.String("protocol", "oidc"))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid_state_token"})
		return
	}

	loginReq, loginReqErr := h.AuthUse.GetLoginRequest(c, loginChallenge)
	if loginReqErr != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "session_expired"})
		return
	}

	userInfo, err := h.clientUseCase.ExchangeAndUserInfo(c.Request.Context(), tenantID, code, connectionID)
	if err != nil {
		logger.FromGin(c).Error("OIDC Exchange Failed", zap.Error(err), zap.String("protocol", "oidc"))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "token_exchange_failed", "details": err.Error()})
		return
	}

	conn, connErr := h.OIDCUse.GetConnection(c, tenantID, connectionID)
	if connErr != nil {
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
	h.wh.FireEvent(tenantID, "user.login.ext", finalAttributes)
	h.AuditLogger.Log(tenantID, subject, "auth.federated.oidc.success", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{
		"connection_id": connectionID,
		"email":         finalAttributes["email"],
	})

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
	_, err = h.AuthUse.CreateLoginRequest(c, loginReq)
	if err != nil {
		logger.FromGin(c).Error("Failed to update login request", zap.Error(err), zap.String("protocol", "oidc"))
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	var redirectTo string

	if loginReq.Protocol == "saml" {
		redirectTo = fmt.Sprintf("%s/t/%s/saml/resume?login_challenge=%s",
			strings.TrimSuffix(h.Config.BaseIssuerURL, "/"),
			tenantID,
			loginReq.ID,
		)
	} else {
		redirectPath := loginReq.RequestURL
		if !strings.HasPrefix(redirectPath, "http") {
			base := strings.TrimSuffix(h.Config.BaseIssuerURL, "/")
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
