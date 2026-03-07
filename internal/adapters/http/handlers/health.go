package handlers

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type HealthHandler struct {
	DB *gorm.DB
}

func NewHealthHandler(db *gorm.DB) *HealthHandler {
	return &HealthHandler{DB: db}
}

func (h *HealthHandler) Check(c *gin.Context) {
	sqlDB, err := h.DB.DB()
	dbStatus := "connected"
	if err != nil || sqlDB.Ping() != nil {
		dbStatus = "disconnected"
	}

	c.JSON(200, gin.H{
		"status":   "up",
		"database": dbStatus,
		"service":  "Shyntr",
	})
}
