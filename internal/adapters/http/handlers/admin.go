package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/adapters/http/dto"
	"github.com/nevzatcirak/shyntr/internal/adapters/http/response"
	"github.com/nevzatcirak/shyntr/internal/application/port"
	"github.com/nevzatcirak/shyntr/internal/application/usecase"
)

type AdminHandler struct {
	Tenant      usecase.TenantUseCase
	OAuth       usecase.OAuth2ClientUseCase
	AuthReq     usecase.AuthUseCase
	AuditLogger port.AuditLogger
	Config      *config.Config
}

func NewAdminHandler(TenantR usecase.TenantUseCase,
	OAuthR usecase.OAuth2ClientUseCase,
	AuthRR usecase.AuthUseCase, AuditLogger port.AuditLogger, cfg *config.Config) *AdminHandler {
	return &AdminHandler{Tenant: TenantR, OAuth: OAuthR, AuthReq: AuthRR, AuditLogger: AuditLogger, Config: cfg}
}

func (h *AdminHandler) fetchTenant(ctx context.Context, tenantID string) *dto.TenantResponse {
	tenant, _ := h.Tenant.GetTenant(ctx, tenantID)
	return dto.FromDomainTenant(tenant)
}

func (h *AdminHandler) fetchClient(ctx context.Context, clientID string) *dto.OAuth2ClientResponse {
	client, _ := h.OAuth.GetClient(ctx, clientID)
	return dto.FromDomainOAuth2Client(client)
}

func (h *AdminHandler) GetLoginRequest(c *gin.Context) {
	challenge := c.Query("login_challenge")
	if challenge == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "Missing login_challenge parameter", nil))
		return
	}
	req, err := h.AuthReq.GetLoginRequest(c, challenge)
	if err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "Login request not found or expired", err))
		return
	}
	var contextMap map[string]interface{}
	if len(req.Context) > 0 {
		_ = json.Unmarshal(req.Context, &contextMap)
	}

	tenant := h.fetchTenant(c, req.TenantID)
	client := h.fetchClient(c, req.ClientID)

	resp := gin.H{
		"challenge":   req.ID,
		"client_id":   req.ClientID,
		"request_url": req.RequestURL,
		"skip":        req.Skip,
		"scopes":      req.RequestedScope,
		"subject":     req.Subject,
		"context":     contextMap,
		"tenant":      tenant,
		"client":      client,
	}

	c.JSON(http.StatusOK, resp)
}

func (h *AdminHandler) AcceptLoginRequest(c *gin.Context) {
	challenge := c.Query("login_challenge")

	var body dto.AcceptLoginRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	req, err := h.AuthReq.AcceptLoginRequest(c, challenge, body)
	if err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "Login request not found", err))
		return
	}

	h.AuditLogger.Log(req.TenantID, req.Subject, "admin.login.accept", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{
		"challenge": challenge,
		"client_id": req.ClientID,
		"protocol":  req.Protocol,
	})

	var redirectTo string

	if req.Protocol == "saml" {
		redirectTo = fmt.Sprintf("%s/t/%s/saml/resume?login_challenge=%s",
			strings.TrimSuffix(h.Config.BaseIssuerURL, "/"),
			req.TenantID,
			req.ID,
		)
	} else {
		redirectPath := req.RequestURL
		if !strings.HasPrefix(redirectPath, "http") {
			base := strings.TrimSuffix(h.Config.BaseIssuerURL, "/")
			if !strings.HasPrefix(redirectPath, "/") {
				redirectPath = "/" + redirectPath
			}
			redirectPath = base + redirectPath
		}
		if strings.Contains(redirectPath, "?") {
			redirectTo = fmt.Sprintf("%s&login_verifier=%s", redirectPath, req.ID)
		} else {
			redirectTo = fmt.Sprintf("%s?login_verifier=%s", redirectPath, req.ID)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"redirect_to": redirectTo,
	})
}

func (h *AdminHandler) RejectLoginRequest(c *gin.Context) {
	challenge := c.Query("login_challenge")
	req, err := h.AuthReq.RejectLoginRequest(c, challenge)
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to reject login request", err))
		return
	}
	h.AuditLogger.Log(req.TenantID, req.Subject, "admin.login.reject", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{
		"challenge": challenge,
		"client_id": req.ClientID,
	})

	c.JSON(http.StatusOK, gin.H{
		"redirect_to": h.Config.BaseIssuerURL + "/oauth2/auth?error=access_denied&error_description=User+rejected+login",
	})
}

func (h *AdminHandler) GetConsentRequest(c *gin.Context) {
	challenge := c.Query("consent_challenge")
	if challenge == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "Missing consent_challenge parameter", nil))
		return
	}

	req, err := h.AuthReq.GetConsentRequest(c, challenge)
	if err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "Consent request not found or expired", err))
		return
	}

	client := h.fetchClient(c, req.ClientID)

	c.JSON(http.StatusOK, gin.H{
		"challenge":          req.ID,
		"client_id":          req.ClientID,
		"subject":            req.Subject,
		"requested_scope":    req.RequestedScope,
		"requested_audience": req.RequestedAudience,
		"skip":               req.Skip,
		"request_url":        req.RequestURL,
		"client":             client,
		"tenant":             client.TenantID,
	})
}

func (h *AdminHandler) AcceptConsentRequest(c *gin.Context) {
	challenge := c.Query("consent_challenge")
	if challenge == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "Missing consent_challenge parameter", nil))
		return
	}

	var body dto.AcceptConsentRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	req, err := h.AuthReq.AcceptConsentRequest(c, challenge, body)
	if err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "Consent request not found", err))
		return
	}

	h.AuditLogger.Log("", req.Subject, "admin.consent.accept", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{
		"challenge":        challenge,
		"client_id":        req.ClientID,
		"granted_scopes":   req.GrantedScope,
		"granted_audience": req.GrantedAudience,
	})

	redirectPath := req.RequestURL
	if !strings.HasPrefix(redirectPath, "http") {
		redirectPath = fmt.Sprintf("%s%s", h.Config.BaseIssuerURL, req.RequestURL)
	}

	redirectTo := fmt.Sprintf("%s&consent_verifier=%s", redirectPath, req.ID)

	c.JSON(http.StatusOK, gin.H{
		"redirect_to": redirectTo,
	})
}

func (h *AdminHandler) RejectConsentRequest(c *gin.Context) {
	challenge := c.Query("consent_challenge")
	if challenge == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "Missing consent_challenge parameter", nil))
		return
	}

	req, err := h.AuthReq.RejectConsentRequest(c, challenge)
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to reject consent request", err))
		return
	}
	h.AuditLogger.Log("", req.Subject, "admin.consent.reject", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{
		"challenge": challenge,
		"client_id": req.ClientID,
	})

	c.JSON(http.StatusOK, gin.H{
		"redirect_to": h.Config.BaseIssuerURL + "/oauth2/auth?error=access_denied&error_description=User+denied+access",
	})
}
