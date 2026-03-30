package handlers

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/http/payload"
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

// GetLoginRequest godoc
// @Summary Get OAuth2 Login Request
// @Description Retrieves the details of an active OAuth2 login challenge. Acts as an internal IdP trust boundary.
// @Tags Auth-Admin
// @Produce json
// @Param login_challenge query string true "The cryptographic login challenge ID"
// @Success 200 {object} map[string]interface{} "Returns the login request details"
// @Failure 400 {object} payload.AppError "login_challenge is required"
// @Failure 404 {object} payload.AppError "Login request not found"
// @Router /admin/login [get]
func (h *AdminHandler) GetLoginRequest(c *gin.Context) {
	challenge := c.Query("login_challenge")
	if challenge == "" {
		c.Error(payload.NewRequiredQueryParamError("login_challenge"))
		return
	}
	req, err := h.AuthReqUseCase.GetLoginRequest(c.Request.Context(), challenge)
	if err != nil {
		c.Error(payload.NewNotFoundAppError("Login request", err))
		return
	}

	c.JSON(http.StatusOK, req)
}

// AcceptLoginRequest godoc
// @Summary Accept OAuth2 Login Request
// @Description Accepts a login request and confirms the user's identity. Returns a redirection URL to continue the OAuth2 flow.
// @Tags Auth-Admin
// @Accept json
// @Produce json
// @Param login_challenge query string true "The cryptographic login challenge ID"
// @Param request body payload.AcceptLoginRequest true "Login acceptance payload containing subject and session preferences"
// @Success 200 {object} map[string]string "Returns redirect_to URL containing the login verifier"
// @Failure 400 {object} payload.AppError "Invalid request payload or missing challenge"
// @Failure 500 {object} payload.AppError "Failed to accept login request"
// @Router /admin/login/accept [put]
func (h *AdminHandler) AcceptLoginRequest(c *gin.Context) {
	challenge := c.Query("login_challenge")
	if challenge == "" {
		c.Error(payload.NewRequiredQueryParamError("login_challenge"))
		return
	}

	var req payload.AcceptLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(payload.NewValidationAppError(err))
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
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "Login request", "complete", err))
		return
	}

	logger.FromGin(c).Info("Login request accepted", zap.String("challenge", challenge), zap.String("subject", req.Subject))

	redirectURL := buildRedirectURL(h.Config.BaseIssuerURL, loginReq.RequestURL, map[string]string{
		"login_verifier": loginReq.ID,
	})
	c.JSON(http.StatusOK, gin.H{"redirect_to": redirectURL})
}

// RejectLoginRequest godoc
// @Summary Reject OAuth2 Login Request
// @Description Rejects a login request (e.g., due to invalid credentials or user denial) and aborts the OAuth2 flow.
// @Tags Auth-Admin
// @Accept json
// @Produce json
// @Param login_challenge query string true "The cryptographic login challenge ID"
// @Param request body payload.RejectRequestPayload true "Rejection payload containing error code and description"
// @Success 200 {object} map[string]string "Returns redirect_to URL containing error details"
// @Failure 400 {object} payload.AppError "Invalid request payload or missing challenge"
// @Failure 500 {object} payload.AppError "Failed to reject login request"
// @Router /admin/login/reject [put]
func (h *AdminHandler) RejectLoginRequest(c *gin.Context) {
	challenge := c.Query("login_challenge")
	if challenge == "" {
		c.Error(payload.NewRequiredQueryParamError("login_challenge"))
		return
	}

	var req payload.RejectRequestPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(payload.NewValidationAppError(err))
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
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "Login request", "complete", err))
		return
	}

	redirectURL := buildRedirectURL(h.Config.BaseIssuerURL, loginReq.RequestURL, map[string]string{
		"error":             req.Error,
		"error_description": req.ErrorDescription,
	})
	c.JSON(http.StatusOK, gin.H{"redirect_to": redirectURL})
}

// GetConsentRequest godoc
// @Summary Get OAuth2 Consent Request
// @Description Retrieves the details of an active OAuth2 consent challenge, including requested scopes and client tenant context.
// @Tags Auth-Admin
// @Produce json
// @Param consent_challenge query string true "The cryptographic consent challenge ID"
// @Success 200 {object} map[string]interface{} "Returns consent request details along with client and tenant information"
// @Failure 400 {object} payload.AppError "consent_challenge is required"
// @Failure 404 {object} payload.AppError "Consent request not found"
// @Failure 500 {object} payload.AppError "Failed to fetch client details"
// @Router /admin/consent [get]
func (h *AdminHandler) GetConsentRequest(c *gin.Context) {
	challenge := c.Query("consent_challenge")
	if challenge == "" {
		c.Error(payload.NewRequiredQueryParamError("consent_challenge"))
		return
	}

	req, err := h.AuthReqUseCase.GetConsentRequest(c.Request.Context(), challenge)
	if err != nil {
		c.Error(payload.NewNotFoundAppError("Consent request", err))
		return
	}

	client, err := h.OAuth2ClientUse.GetClient(c.Request.Context(), req.ClientID)
	if err != nil {
		c.Error(payload.NewOperationAppError(http.StatusConflict, "Client details", "load", err))
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

// AcceptConsentRequest godoc
// @Summary Accept OAuth2 Consent Request
// @Description Accepts a consent request, granting the requested scopes and audiences to the OAuth2 client.
// @Tags Auth-Admin
// @Accept json
// @Produce json
// @Param consent_challenge query string true "The cryptographic consent challenge ID"
// @Param request body payload.AcceptConsentRequest true "Consent acceptance payload with granted scopes/audiences"
// @Success 200 {object} map[string]string "Returns redirect_to URL containing the consent verifier"
// @Failure 400 {object} payload.AppError "Invalid request payload or missing challenge"
// @Failure 500 {object} payload.AppError "Failed to accept consent request"
// @Router /admin/consent/accept [put]
func (h *AdminHandler) AcceptConsentRequest(c *gin.Context) {
	challenge := c.Query("consent_challenge")
	if challenge == "" {
		c.Error(payload.NewRequiredQueryParamError("consent_challenge"))
		return
	}

	var req payload.AcceptConsentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(payload.NewValidationAppError(err))
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
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "Consent request", "complete", err))
		return
	}

	logger.FromGin(c).Info("Consent request accepted", zap.String("challenge", challenge))

	redirectURL := buildRedirectURL(h.Config.BaseIssuerURL, consentReq.RequestURL, map[string]string{
		"consent_verifier": consentReq.ID,
	})
	c.JSON(http.StatusOK, gin.H{"redirect_to": redirectURL})
}

// RejectConsentRequest godoc
// @Summary Reject OAuth2 Consent Request
// @Description Rejects a consent request (e.g., user denied access to scopes) and aborts the OAuth2 flow.
// @Tags Auth-Admin
// @Accept json
// @Produce json
// @Param consent_challenge query string true "The cryptographic consent challenge ID"
// @Param request body payload.RejectRequestPayload true "Rejection payload containing error code and description"
// @Success 200 {object} map[string]string "Returns redirect_to URL containing error details"
// @Failure 400 {object} payload.AppError "Invalid request payload or missing challenge"
// @Failure 500 {object} payload.AppError "Failed to reject consent request"
// @Router /admin/consent/reject [put]
func (h *AdminHandler) RejectConsentRequest(c *gin.Context) {
	challenge := c.Query("consent_challenge")
	if challenge == "" {
		c.Error(payload.NewRequiredQueryParamError("consent_challenge"))
		return
	}

	var req payload.RejectRequestPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(payload.NewValidationAppError(err))
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
		c.Error(payload.NewOperationAppError(http.StatusBadRequest, "Consent request", "complete", err))
		return
	}
	logger.FromGin(c).Info("Consent request rejected", zap.String("challenge", challenge), zap.String("error", req.Error))

	redirectURL := buildRedirectURL(h.Config.BaseIssuerURL, consentReq.RequestURL, map[string]string{
		"error":             req.Error,
		"error_description": req.ErrorDescription,
	})
	c.JSON(http.StatusOK, gin.H{"redirect_to": redirectURL})
}

// buildRedirectURL constructs a safe redirect URL by taking the path from requestURL,
// stripping the host to prevent open redirects, and appending the provided query params.
func buildRedirectURL(baseIssuerURL, requestURL string, params map[string]string) string {
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return baseIssuerURL
	}

	safePath := parsed.Path
	if safePath == "" {
		safePath = "/"
	} else if !strings.HasPrefix(safePath, "/") {
		safePath = "/" + safePath
	}

	q := parsed.Query()
	for k, v := range params {
		q.Set(k, v)
	}

	base := strings.TrimRight(baseIssuerURL, "/")
	return base + safePath + "?" + q.Encode()
}
