package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/http/payload"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type WebhookHandler struct {
	webhookUse usecase.WebhookUseCase
	cfg        *config.Config
}

type CreateWebhookRequest struct {
	Name      string   `json:"name" binding:"required"`
	URL       string   `json:"url" binding:"required,url"`
	TenantIDs []string `json:"tenant_ids" binding:"required"`
	Events    []string `json:"events" binding:"required"`
}

func NewWebhookHandler(webhookUse usecase.WebhookUseCase, cfg *config.Config) *WebhookHandler {
	return &WebhookHandler{
		webhookUse: webhookUse,
		cfg:        cfg,
	}
}

func isSafeWebhookURL(target string, allowPrivate bool) bool {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}

	ips, err := net.LookupIP(parsed.Hostname())
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.Equal(net.ParseIP("169.254.169.254")) {
			if allowPrivate {
				continue
			}
			return false
		}
	}
	return true
}

// Create godoc
// @Summary Create Webhook Destination
// @Description Registers a new webhook endpoint for event dispatching. Includes strict SSRF protection to prevent internal network scanning.
// @Tags Webhook
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateWebhookRequest true "Webhook configuration payload including target URL, events, and bound tenants"
// @Success 201 {object} model.Webhook "Successfully created webhook (returns secret ONLY ONCE for signature verification)"
// @Failure 400 {object} map[string]string "error - Invalid payload or SSRF blocked (resolves to internal IP)"
// @Failure 500 {object} map[string]string "error - Failed to create webhook"
// @Router /webhooks [post]
func (h *WebhookHandler) Create(c *gin.Context) {
	var req CreateWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		payload.AbortWithAppError(c, payload.NewValidationAppError(err))
		return
	}

	isDevMode := h.cfg.DEVELOPMENT == "true"

	if !isSafeWebhookURL(req.URL, isDevMode) {
		payload.AbortWithAppError(c, payload.NewDetailedAppError(http.StatusBadRequest, "invalid_webhook_url", "The webhook URL is blocked because it resolves to an internal or restricted address.", "Use a public HTTP or HTTPS endpoint that is allowed by the outbound security policy.", []payload.FieldError{{Field: "url", Message: "Must resolve to a public and allowed destination."}}, nil))
		return
	}

	secretBytes := make([]byte, 32)
	rand.Read(secretBytes)
	secret := hex.EncodeToString(secretBytes)

	wh := model.Webhook{
		ID:        "wh_" + strings.ReplaceAll(uuid.New().String(), "-", ""),
		Name:      req.Name,
		URL:       req.URL,
		Secret:    secret,
		TenantIDs: req.TenantIDs,
		Events:    req.Events,
		IsActive:  true,
	}

	webhook, _, err := h.webhookUse.CreateWebhook(c.Request.Context(), &wh, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		payload.AbortWithAppError(c, payload.NewOperationAppError(http.StatusBadRequest, "Webhook", "create", err))
		return
	}

	c.JSON(http.StatusCreated, webhook)
}
