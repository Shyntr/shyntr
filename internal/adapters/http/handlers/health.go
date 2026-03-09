package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/internal/application/usecase"
)

type HealthHandler struct {
	healthUse usecase.HealthUseCase
}

func NewHealthHandler(healthUse usecase.HealthUseCase) *HealthHandler {
	return &HealthHandler{healthUse: healthUse}
}

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
