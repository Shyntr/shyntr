package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/application/usecase"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
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
func (h *WebhookHandler) Create(c *gin.Context) {
	var req CreateWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	isDevMode := h.cfg.DEVELOPMENT == "true"

	if !isSafeWebhookURL(req.URL, isDevMode) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_webhook_url: target resolves to an internal or restricted IP address (SSRF blocked)"})
		return
	}

	secretBytes := make([]byte, 32)
	rand.Read(secretBytes)
	secret := hex.EncodeToString(secretBytes)

	wh := entity.Webhook{
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create webhook"})
		return
	}

	c.JSON(http.StatusCreated, webhook)
}
