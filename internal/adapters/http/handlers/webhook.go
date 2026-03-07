package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nevzatcirak/shyntr/internal/application/port"
	"github.com/nevzatcirak/shyntr/internal/application/usecase"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
)

type WebhookHandler struct {
	audit      port.AuditLogger
	webhookUse usecase.WebhookUseCase
}

type CreateWebhookRequest struct {
	Name      string   `json:"name" binding:"required"`
	URL       string   `json:"url" binding:"required,url"`
	TenantIDs []string `json:"tenant_ids" binding:"required"`
	Events    []string `json:"events" binding:"required"`
}

func NewWebhookHandler(audit port.AuditLogger, webhookUse usecase.WebhookUseCase) *WebhookHandler {
	return &WebhookHandler{audit: audit, webhookUse: webhookUse}
}

func (h *WebhookHandler) Create(c *gin.Context) {
	var req CreateWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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

	webhook, _, err := h.webhookUse.CreateWebhook(c, &wh, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create webhook"})
		return
	}

	h.audit.Log("system", "admin_api", "management.webhook.create", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{
		"webhook_id": webhook.ID,
		"url":        webhook.URL,
		"events":     webhook.Events,
	})

	c.JSON(http.StatusCreated, webhook)
}
