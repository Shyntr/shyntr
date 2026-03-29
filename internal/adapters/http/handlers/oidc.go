package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/http/payload"
	"github.com/Shyntr/shyntr/internal/application/mapper"
	"github.com/Shyntr/shyntr/internal/application/security"
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
	StateProvider security.FederationStateProvider
}

func NewOIDCHandler(Config *config.Config, clientUseCase usecase.OAuth2ClientUseCase, AuthUse usecase.AuthUseCase,
	OIDCUse usecase.OIDCConnectionUseCase, m *mapper.Mapper, wh usecase.WebhookUseCase, StateProvider security.FederationStateProvider) *OIDCHandler {
	return &OIDCHandler{Config: Config, clientUseCase: clientUseCase, AuthUse: AuthUse, OIDCUse: OIDCUse, Mapper: m, wh: wh, StateProvider: StateProvider}
}

// Login godoc
// @Summary Initiate OIDC Federation Login
// @Description Starts the login flow with an external OIDC Identity Provider (e.g., Google, Okta) for a specific tenant and connection. Generates CSRF tokens and redirects the user.
// @Tags OIDC Federation
// @Produce html
// @Param tenant_id path string true "Tenant ID"
// @Param connection_id path string true "OIDC Connection ID"
// @Param login_challenge query string true "The active cryptographic login challenge ID"
// @Success 302 {string} string "Redirects the user agent to the external Identity Provider's authorization endpoint"
// @Failure 400 {object} map[string]string "Bad Request (missing tenant_id or login_challenge)"
// @Failure 404 {object} map[string]string "Not Found (login request not found)"
// @Failure 500 {object} map[string]string "Internal Server Error (failed to initiate OIDC)"
// @Router /t/{tenant_id}/oidc/login/{connection_id} [get]
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

	csrfToken, err := utils.GenerateRandomHex(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "csrf_generation_failed"})
		return
	}

	c.SetCookie("shyntr_fed_csrf", csrfToken, 600, "/", "", h.Config.CookieSecure, true)

	state, err := h.StateProvider.Issue(c.Request.Context(), security.IssueFederationStateInput{
		Action:         security.FederationActionOIDCLogin,
		TenantID:       tenantID,
		LoginChallenge: loginChallenge,
		ConnectionID:   connectionID,
		CSRFToken:      csrfToken,
		TTL:            10 * time.Minute,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "state_issue_failed"})
		return
	}

	redirectURL, providerCtx, err := h.clientUseCase.InitiateAuth(c.Request.Context(), tenantID, connectionID, state, csrfToken)
	if err != nil {
		logger.FromGin(c).Error("Failed to initiate OIDC", zap.Error(err), zap.String("protocol", "oidc"))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "oidc_init_failed", "details": err.Error()})
		return
	}

	_ = h.AuthUse.MarkLoginAsProviderStarted(c.Request.Context(), loginReq.ID, "oidc", connectionID, providerCtx, c.ClientIP(), c.Request.UserAgent())
	c.Redirect(http.StatusFound, redirectURL)
}

// Callback godoc
// @Summary OIDC Federation Callback
// @Description Handles the callback from an external OIDC Identity Provider. Validates state and CSRF, exchanges the authorization code for tokens, fetches UserInfo, maps attributes, and resumes the original login flow.
// @Tags OIDC Federation
// @Produce html
// @Param tenant_id path string true "Tenant ID"
// @Param code query string true "Authorization code returned by the external IdP"
// @Param state query string true "State parameter to mitigate CSRF and restore context"
// @Success 302 {string} string "Redirects back to the original protocol handler (SAML or OAuth2) with a login_verifier"
// @Failure 400 {object} map[string]string "Bad Request (invalid or missing callback parameters)"
// @Failure 403 {object} map[string]string "Forbidden (CSRF validation failed, invalid state, or session expired)"
// @Failure 500 {object} payload.AppError "Internal Server Error (connection not found or mapping failed)"
// @Router /t/{tenant_id}/oidc/callback [get]
func (h *OIDCHandler) Callback(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
		return
	}
	providerError := c.Query("error")
	if providerError != "" {
		errorDescription := c.Query("error_description")
		logger.FromGin(c).Warn("OIDC provider returned error",
			zap.String("protocol", "oidc"),
			zap.String("error", providerError),
			zap.String("error_description", errorDescription),
		)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error":             providerError,
			"error_description": errorDescription,
		})
		return
	}
	code := c.Query("code")
	stateToken := c.Query("state")

	if stateToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_state"})
		return
	}

	if code == "" {
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

	verifiedState, err := h.StateProvider.Verify(c.Request.Context(), stateToken, security.VerifyFederationStateInput{
		ExpectedAction: security.FederationActionOIDCLogin,
		ExpectedTenant: tenantID,
		CSRFToken:      csrfCookie,
	})
	if err != nil {
		logger.FromGin(c).Warn("OIDC callback federation state validation failed",
			zap.Error(err),
			zap.String("protocol", "oidc"),
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid_state"})
		return
	}

	loginChallenge := verifiedState.LoginChallenge
	connectionID := verifiedState.ConnectionID
	loginReq, loginReqErr := h.AuthUse.GetLoginRequest(c.Request.Context(), loginChallenge)
	if loginReqErr != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "session_expired"})
		return
	}

	var ctxData map[string]interface{}
	if len(loginReq.Context) > 0 {
		_ = json.Unmarshal(loginReq.Context, &ctxData)
	}
	if ctxData == nil {
		ctxData = make(map[string]interface{})
	}
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
	loginReq, err = h.AuthUse.CompleteProviderLogin(c.Request.Context(), loginChallenge, subject, conn.Name, existingCtx, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		logger.FromGin(c).Error("Failed to update login request", zap.Error(err), zap.String("protocol", "oidc"))
		c.Error(payload.NewAppError(http.StatusInternalServerError, "Failed to complete OIDC login", err))
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
