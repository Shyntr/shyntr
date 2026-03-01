package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"gorm.io/gorm"
)

type WebhookHandler struct {
	DB *gorm.DB
}

type CreateWebhookRequest struct {
	Name      string   `json:"name" binding:"required"`
	URL       string   `json:"url" binding:"required,url"`
	TenantIDs []string `json:"tenant_ids" binding:"required"`
	Events    []string `json:"events" binding:"required"`
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

	wh := models.Webhook{
		ID:        "wh_" + strings.ReplaceAll(uuid.New().String(), "-", ""),
		Name:      req.Name,
		URL:       req.URL,
		Secret:    secret,
		TenantIDs: req.TenantIDs,
		Events:    req.Events,
		IsActive:  true,
	}

	if err := h.DB.Create(&wh).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create webhook"})
		return
	}

	c.JSON(http.StatusCreated, wh)
}
