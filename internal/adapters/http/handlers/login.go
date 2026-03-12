package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/adapters/http/response"
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
		c.Error(response.NewAppError(http.StatusBadRequest, "missing_login_challenge", nil))
		return
	}

	methods, loginReq, err := h.MUC.GetLoginMethods(c.Request.Context(), challenge)
	if err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, err.Error(), nil))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"challenge": loginReq.ID,
		"tenant_id": loginReq.TenantID,
		"methods":   methods,
	})
}
