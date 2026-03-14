package handlers

import (
	"net/http"

	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/gin-gonic/gin"
)

type HealthHandler struct {
	healthUse usecase.HealthUseCase
}

func NewHealthHandler(healthUse usecase.HealthUseCase) *HealthHandler {
	return &HealthHandler{healthUse: healthUse}
}

// Check godoc
// @Summary Health Check
// @Description Evaluates the health of the Shyntr service and its underlying database connection. This is a public endpoint used for observability and orchestration readiness probes.
// @Tags Health
// @Produce json
// @Success 200 {object} map[string]string "Returns service and database connection status"
// @Router /health [get]
func (h *HealthHandler) Check(c *gin.Context) {
	dbStatus := "connected"
	if err := h.healthUse.CheckDatabase(c.Request.Context()); err != nil {
		dbStatus = "disconnected"
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "up",
		"database": dbStatus,
		"service":  "Shyntr",
	})
}
