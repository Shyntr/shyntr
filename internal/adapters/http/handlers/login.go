package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/application/usecase"
)

type LoginHandler struct {
	Config *config.Config
	MUC    usecase.ManagementUseCase
}

func NewLoginHandler(cfg *config.Config, MUC usecase.ManagementUseCase) *LoginHandler {
	return &LoginHandler{Config: cfg, MUC: MUC}
}

func (h *LoginHandler) GetLoginMethods(c *gin.Context) {
	challenge := c.Query("login_challenge")
	if challenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_login_challenge"})
		return
	}

	methods, loginReq, err := h.MUC.GetLoginMethods(c, challenge)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	c.JSON(http.StatusOK, gin.H{
		"challenge": loginReq.ID,
		"tenant_id": loginReq.TenantID,
		"methods":   methods,
	})
}
