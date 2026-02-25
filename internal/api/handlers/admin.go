package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/api/response"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"gorm.io/gorm"
)

type AdminHandler struct {
	DB     *gorm.DB
	Config *config.Config
}

func NewAdminHandler(db *gorm.DB, cfg *config.Config) *AdminHandler {
	return &AdminHandler{DB: db, Config: cfg}
}

func (h *AdminHandler) fetchTenant(tenantID string) *models.Tenant {
	var tenant models.Tenant
	if err := h.DB.First(&tenant, "id = ?", tenantID).Error; err != nil {
		return nil
	}
	return &tenant
}

func (h *AdminHandler) fetchClient(clientID string) *models.OAuth2Client {
	var client models.OAuth2Client
	if err := h.DB.First(&client, "id = ?", clientID).Error; err != nil {
		return nil
	}
	return &client
}

func (h *AdminHandler) GetLoginRequest(c *gin.Context) {
	challenge := c.Query("login_challenge")
	if challenge == "" {
		c.Error(response.NewAppError(http.StatusBadRequest, "Missing login_challenge parameter", nil))
		return
	}

	var req models.LoginRequest
	if err := h.DB.First(&req, "id = ?", challenge).Error; err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "Login request not found or expired", err))
		return
	}

	var contextMap map[string]interface{}
	if len(req.Context) > 0 {
		_ = json.Unmarshal(req.Context, &contextMap)
	}

	tenant := h.fetchTenant(req.TenantID)
	client := h.fetchClient(req.ClientID)

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

	var body struct {
		Subject     string                 `json:"subject" binding:"required"`
		Remember    bool                   `json:"remember"`
		RememberFor int                    `json:"remember_for"`
		Context     map[string]interface{} `json:"context"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	var req models.LoginRequest
	if err := h.DB.First(&req, "id = ?", challenge).Error; err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "Login request not found", err))
		return
	}

	req.Subject = body.Subject
	req.Authenticated = true
	req.Remember = body.Remember
	req.RememberFor = body.RememberFor

	if body.Context != nil {
		var existingCtx map[string]interface{}
		if len(req.Context) > 0 {
			_ = json.Unmarshal(req.Context, &existingCtx)
		} else {
			existingCtx = make(map[string]interface{})
		}
		existingCtx["login_claims"] = body.Context
		mergedBytes, _ := json.Marshal(existingCtx)
		req.Context = mergedBytes
	}

	if err := h.DB.Save(&req).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to update login request", err))
		return
	}

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
	if err := h.DB.Model(&models.LoginRequest{}).Where("id = ?", challenge).Updates(map[string]interface{}{
		"active": false,
	}).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to reject login request", err))
		return
	}

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

	var req models.ConsentRequest
	if err := h.DB.First(&req, "id = ?", challenge).Error; err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "Consent request not found or expired", err))
		return
	}

	client := h.fetchClient(req.ClientID)
	var tenant *models.Tenant
	if client != nil {
		tenant = h.fetchTenant(client.TenantID)
	}

	c.JSON(http.StatusOK, gin.H{
		"challenge":          req.ID,
		"client_id":          req.ClientID,
		"subject":            req.Subject,
		"requested_scope":    req.RequestedScope,
		"requested_audience": req.RequestedAudience,
		"skip":               req.Skip,
		"request_url":        req.RequestURL,
		"client":             client,
		"tenant":             tenant,
	})
}

func (h *AdminHandler) AcceptConsentRequest(c *gin.Context) {
	challenge := c.Query("consent_challenge")
	var body struct {
		GrantScope    []string `json:"grant_scope"`
		GrantAudience []string `json:"grant_audience"`
		Remember      bool     `json:"remember"`
		RememberFor   int      `json:"remember_for"`
		Session       *struct {
			AccessToken map[string]any `json:"access_token"`
			IDToken     map[string]any `json:"id_token"`
		} `json:"session,omitempty"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid request payload", err))
		return
	}

	var req models.ConsentRequest
	if err := h.DB.First(&req, "id = ?", challenge).Error; err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "Consent request not found", err))
		return
	}

	req.GrantedScope = body.GrantScope
	req.GrantedAudience = body.GrantAudience
	req.Authenticated = true
	req.Active = true
	req.Remember = body.Remember
	req.RememberFor = body.RememberFor
	sessionBytes, err := json.Marshal(body.Session)
	if err == nil {
		req.Context = sessionBytes
	}

	if err := h.DB.Save(&req).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to update consent request", err))
		return
	}

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

	if err := h.DB.Model(&models.ConsentRequest{}).Where("id = ?", challenge).Updates(map[string]interface{}{
		"active": false,
	}).Error; err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to reject consent request", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"redirect_to": h.Config.BaseIssuerURL + "/oauth2/auth?error=access_denied&error_description=User+denied+access",
	})
}
