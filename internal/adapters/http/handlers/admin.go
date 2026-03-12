package handlers

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/http/dto"
	"github.com/Shyntr/shyntr/internal/adapters/http/response"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type AdminHandler struct {
	TenantUse       usecase.TenantUseCase
	OAuth2ClientUse usecase.OAuth2ClientUseCase
	AuthReqUseCase  usecase.AuthUseCase
	Config          *config.Config
}

func NewAdminHandler(TenantUse usecase.TenantUseCase, OAuth2ClientUse usecase.OAuth2ClientUseCase, AuthReqUseCase usecase.AuthUseCase, Config *config.Config) *AdminHandler {
	return &AdminHandler{
		TenantUse:       TenantUse,
		OAuth2ClientUse: OAuth2ClientUse,
		AuthReqUseCase:  AuthReqUseCase,
		Config:          Config,
	}

}

// --- Login API ---

func (h *AdminHandler) GetLoginRequest(c *gin.Context) {
	challenge := c.Query("login_challenge")
	if challenge == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "login_challenge is required", nil))
		return
	}
	req, err := h.AuthReqUseCase.GetLoginRequest(c.Request.Context(), challenge)
	if err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "Login request not found", err))
		return
	}

	c.JSON(http.StatusOK, req)
}

func (h *AdminHandler) AcceptLoginRequest(c *gin.Context) {
	challenge := c.Query("login_challenge")
	if challenge == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "login_challenge is required", nil))
		return
	}

	var req dto.AcceptLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	loginReq, err := h.AuthReqUseCase.AcceptLoginRequest(
		c.Request.Context(),
		challenge,
		req.Remember,
		req.RememberFor,
		req.Subject,
		req.Context,
		c.ClientIP(),
		c.Request.UserAgent(),
	)
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to accept login request", err))
		return
	}

	logger.FromGin(c).Info("Login request accepted", zap.String("challenge", challenge), zap.String("subject", req.Subject))

	redirectURL := buildRedirectURL(h.Config.BaseIssuerURL, loginReq.RequestURL, map[string]string{
		"login_verifier": loginReq.ID,
	})
	c.JSON(http.StatusOK, gin.H{"redirect_to": redirectURL})
}

func (h *AdminHandler) RejectLoginRequest(c *gin.Context) {
	challenge := c.Query("login_challenge")
	if challenge == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "login_challenge is required", nil))
		return
	}

	var req dto.RejectRequestPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	loginReq, err := h.AuthReqUseCase.RejectLoginRequest(
		c.Request.Context(),
		challenge,
		req.Error,
		req.ErrorDescription,
		c.ClientIP(),
		c.Request.UserAgent(),
	)
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to reject login request", err))
		return
	}
	logger.FromGin(c).Info("Login request rejected", zap.String("challenge", challenge), zap.String("error", req.Error))

	redirectURL := buildRedirectURL(h.Config.BaseIssuerURL, loginReq.RequestURL, map[string]string{
		"error":             req.Error,
		"error_description": req.ErrorDescription,
	})
	c.JSON(http.StatusOK, gin.H{"redirect_to": redirectURL})
}

// --- Consent API ---
func (h *AdminHandler) GetConsentRequest(c *gin.Context) {
	challenge := c.Query("consent_challenge")
	if challenge == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "consent_challenge is required", nil))
		return
	}

	req, err := h.AuthReqUseCase.GetConsentRequest(c.Request.Context(), challenge)
	if err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "Consent request not found", err))
		return
	}

	client, err := h.OAuth2ClientUse.GetClient(c.Request.Context(), req.ClientID)
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to fetch client details", err))
		return
	}

	responsePayload := map[string]interface{}{
		"challenge":          req.ID,
		"client_id":          req.ClientID,
		"subject":            req.Subject,
		"requested_scope":    req.RequestedScope,
		"requested_audience": req.RequestedAudience,
		"skip":               req.Skip,
		"request_url":        req.RequestURL,
		"client":             client,
		"tenant":             client.TenantID,
	}

	c.JSON(http.StatusOK, responsePayload)
}

func (h *AdminHandler) AcceptConsentRequest(c *gin.Context) {
	challenge := c.Query("consent_challenge")
	if challenge == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "consent_challenge is required", nil))
		return
	}

	var req dto.AcceptConsentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	consentReq, err := h.AuthReqUseCase.AcceptConsentRequest(
		c.Request.Context(),
		challenge,
		req.GrantScope,
		req.GrantAudience,
		req.Remember,
		req.RememberFor,
		req.Session,
		c.ClientIP(),
		c.Request.UserAgent(),
	)
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to accept consent request", err))
		return
	}

	logger.FromGin(c).Info("Consent request accepted", zap.String("challenge", challenge))

	redirectURL := buildRedirectURL(h.Config.BaseIssuerURL, consentReq.RequestURL, map[string]string{
		"consent_verifier": consentReq.ID,
	})
	c.JSON(http.StatusOK, gin.H{"redirect_to": redirectURL})
}

func (h *AdminHandler) RejectConsentRequest(c *gin.Context) {
	challenge := c.Query("consent_challenge")
	if challenge == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "consent_challenge is required", nil))
		return
	}

	var req dto.RejectRequestPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	consentReq, err := h.AuthReqUseCase.RejectConsentRequest(
		c.Request.Context(),
		challenge,
		req.Error,
		req.ErrorDescription,
		c.ClientIP(),
		c.Request.UserAgent(),
	)
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to reject consent request", err))
		return
	}
	logger.FromGin(c).Info("Consent request rejected", zap.String("challenge", challenge), zap.String("error", req.Error))

	redirectURL := buildRedirectURL(h.Config.BaseIssuerURL, consentReq.RequestURL, map[string]string{
		"error":             req.Error,
		"error_description": req.ErrorDescription,
	})
	c.JSON(http.StatusOK, gin.H{"redirect_to": redirectURL})
}

func buildRedirectURL(baseURL, requestURL string, params map[string]string) string {
	parsed, _ := url.Parse(requestURL)
	q := parsed.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	parsed.RawQuery = q.Encode()

	if parsed.IsAbs() {
		return parsed.String()
	}

	base := strings.TrimRight(baseURL, "/")
	path := parsed.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path + "?" + parsed.RawQuery
}
