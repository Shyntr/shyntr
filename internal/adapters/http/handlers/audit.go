package handlers

import (
	"net/http"
	"strconv"

	"github.com/Shyntr/shyntr/internal/adapters/http/payload"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/gin-gonic/gin"
)

type AuditHandler struct {
	audit usecase.AuditUseCase
}

func NewAuditHandler(audit usecase.AuditUseCase) *AuditHandler {
	return &AuditHandler{audit: audit}
}

// Get godoc
// @Summary Get Tenant Audit Logs
// @Description Retrieves paginated audit logs for a specific tenant.
// @Tags Audit
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID for isolation boundary"
// @Param limit query int false "Number of records to return" default(100)
// @Param offset query int false "Number of records to skip" default(0)
// @Success 200 {array} map[string]interface{} "List of tenant audit logs"
// @Failure 500 {object} map[string]string "error - Failed to get audit logs"
// @Router /audit/{tenant_id} [get]
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
		payload.AbortWithAppError(c, payload.NewOperationAppError(http.StatusInternalServerError, "Audit logs", "load", err))
		return
	}
	c.JSON(http.StatusOK, logs)
}
