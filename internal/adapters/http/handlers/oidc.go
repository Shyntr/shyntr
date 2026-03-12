package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/http/response"
	"github.com/Shyntr/shyntr/internal/application/mapper"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/Shyntr/shyntr/pkg/utils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type OIDCHandler struct {
	Config        *config.Config
	clientUseCase usecase.OAuth2ClientUseCase
	AuthUse       usecase.AuthUseCase
	OIDCUse       usecase.OIDCConnectionUseCase
	Mapper        *mapper.Mapper
	wh            usecase.WebhookUseCase
}

func NewOIDCHandler(Config *config.Config, clientUseCase usecase.OAuth2ClientUseCase, AuthUse usecase.AuthUseCase,
	OIDCUse usecase.OIDCConnectionUseCase, m *mapper.Mapper, wh usecase.WebhookUseCase) *OIDCHandler {
	return &OIDCHandler{Config: Config, clientUseCase: clientUseCase, AuthUse: AuthUse, OIDCUse: OIDCUse, Mapper: m, wh: wh}
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

	loginReq, err := h.AuthUse.GetLoginRequest(c.Request.Context(), loginChallenge)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "login_request_not_found"})
		return
	}

	csrfToken, _ := utils.GenerateRandomHex(32)
	c.SetCookie("shyntr_fed_csrf", csrfToken, 600, "/", "", h.Config.CookieSecure, true)

	redirectURL, providerCtx, err := h.clientUseCase.InitiateAuth(c.Request.Context(), tenantID, connectionID, loginChallenge, csrfToken)
	if err != nil {
		logger.FromGin(c).Error("Failed to initiate OIDC", zap.Error(err), zap.String("protocol", "oidc"))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "oidc_init_failed", "details": err.Error()})
		return
	}

	_ = h.AuthUse.MarkLoginAsProviderStarted(c.Request.Context(), loginReq.ID, "oidc", connectionID, providerCtx, c.ClientIP(), c.Request.UserAgent())
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

	csrfCookie, err := c.Cookie("shyntr_fed_csrf")
	if err != nil || csrfCookie == "" {
		logger.FromGin(c).Warn("Login CSRF blocked", zap.String("protocol", "oidc"))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "missing_csrf_cookie"})
		return
	}
	c.SetCookie("shyntr_fed_csrf", "", -1, "/", "", h.Config.CookieSecure, true)

	loginChallenge, connectionID, err := h.clientUseCase.VerifyState(state, csrfCookie)
	if err != nil {
		logger.FromGin(c).Warn("Invalid OIDC state", zap.Error(err), zap.String("protocol", "oidc"))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid_state_token"})
		return
	}

	loginReq, loginReqErr := h.AuthUse.GetLoginRequest(c.Request.Context(), loginChallenge)
	if loginReqErr != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "session_expired"})
		return
	}

	var ctxData map[string]interface{}
	json.Unmarshal(loginReq.Context, &ctxData)
	codeVerifier, _ := ctxData["code_verifier"].(string)
	expectedNonce, _ := ctxData["nonce"].(string)

	userInfo, err := h.clientUseCase.ExchangeAndUserInfo(c.Request.Context(), tenantID, code, connectionID, codeVerifier, expectedNonce)
	if err != nil {
		logger.FromGin(c).Error("OIDC Exchange Failed", zap.Error(err), zap.String("protocol", "oidc"))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "token_exchange_failed", "details": err.Error()})
		return
	}

	conn, connErr := h.OIDCUse.GetConnection(c.Request.Context(), tenantID, connectionID)
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

	var existingCtx map[string]interface{}
	if len(loginReq.Context) > 0 {
		_ = json.Unmarshal(loginReq.Context, &existingCtx)
	} else {
		existingCtx = make(map[string]interface{})
	}

	existingCtx["login_claims"] = finalAttributes
	loginReq, err = h.AuthUse.CompleteProviderLogin(c.Request.Context(), loginChallenge, subject, existingCtx, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		logger.FromGin(c).Error("Failed to update login request", zap.Error(err), zap.String("protocol", "oidc"))
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to complete OIDC login", err))
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
		parsedURL, err := url.Parse(loginReq.RequestURL)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "invalid_redirect_url"})
			return
		}

		safePath := parsedURL.Path
		if safePath == "" {
			safePath = "/"
		} else if !strings.HasPrefix(safePath, "/") {
			safePath = "/" + safePath
		}

		query := parsedURL.Query()
		query.Set("login_verifier", loginReq.ID)
		base := strings.TrimSuffix(h.Config.BaseIssuerURL, "/")
		redirectTo = fmt.Sprintf("%s%s?%s", base, safePath, query.Encode())
	}
	c.Redirect(http.StatusFound, redirectTo)
}
