package handlers

import (
	"errors"
	"net/http"

	"github.com/Shyntr/shyntr/config"
	"github.com/Shyntr/shyntr/internal/adapters/http/payload"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/gin-gonic/gin"
)

type LoginHandler struct {
	Config *config.Config
	MUC    usecase.ManagementUseCase
}

func NewLoginHandler(cfg *config.Config, MUC usecase.ManagementUseCase) *LoginHandler {
	return &LoginHandler{Config: cfg, MUC: MUC}
}

// GetLoginMethods godoc
// @Summary Get Login Methods
// @Description Retrieves available identity providers and authentication methods for a given cryptographic login challenge. This discovery endpoint establishes the initial context for the user authentication journey.
// @Tags Auth-Login
// @Produce json
// @Param login_challenge query string true "The cryptographic login challenge ID"
// @Success 200 {object} map[string]interface{} "Returns the challenge ID, tenant ID, and a list of available login methods"
// @Failure 400 {object} payload.AppError "missing_login_challenge or invalid challenge"
// @Router /auth/methods [get]
func (h *LoginHandler) GetLoginMethods(c *gin.Context) {
	challenge := c.Query("login_challenge")
	if challenge == "" {
		c.Error(payload.NewRequiredQueryParamError("login_challenge"))
		return
	}

	methods, loginReq, err := h.MUC.GetLoginMethods(c.Request.Context(), challenge)
	if err != nil {
		if isLoginMethodsClientError(err) {
			c.Error(payload.NewDetailedAppError(
				http.StatusBadRequest,
				"invalid_login_challenge",
				"The login challenge is invalid, expired, or no longer active.",
				"Start the login flow again and use a fresh login_challenge value.",
				nil,
				err,
			))
			return
		}

		c.Error(payload.NewDetailedAppError(
			http.StatusInternalServerError,
			"internal_server_error",
			"Failed to retrieve login methods.",
			"Retry the request. If the problem persists, contact the system administrator.",
			nil,
			err,
		))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"challenge": loginReq.ID,
		"tenant_id": loginReq.TenantID,
		"methods":   methods,
	})
}

func isLoginMethodsClientError(err error) bool {
	return errors.Is(err, usecase.ErrLoginChallengeNotFound) ||
		errors.Is(err, usecase.ErrLoginAlreadyUsed)
}
