package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/internal/application/usecase"
)

type AuditHandler struct {
	audit usecase.AuditUseCase
}

func NewAuditHandler(audit usecase.AuditUseCase) *AuditHandler {
	return &AuditHandler{audit: audit}
}

func (h *AuditHandler) Get(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	limitStr := c.DefaultQuery("limit", "100")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		limit = 100
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil {
		offset = 0
	}
	logs, err := h.audit.GetTenantLogs(c, tenantID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get audit logs"})
		return
	}
	c.JSON(http.StatusOK, logs)
}
