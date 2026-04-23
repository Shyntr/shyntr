package handlers

import (
	"errors"
	"net/http"

	"github.com/Shyntr/shyntr/internal/adapters/http/payload"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// PasswordLoginHandler provides admin CRUD for password login endpoint
// definitions and tenant assignments.
type PasswordLoginHandler struct {
	UseCase usecase.PasswordLoginUseCase
}

func NewPasswordLoginHandler(uc usecase.PasswordLoginUseCase) *PasswordLoginHandler {
	return &PasswordLoginHandler{UseCase: uc}
}

// ----- Endpoint handlers -----

// CreateEndpoint godoc
// @Summary Create password login endpoint
// @Description Defines a new external password verifier endpoint that can be assigned to tenants.
// @Tags Password Login
// @Accept json
// @Produce json
// @Param request body payload.CreatePasswordLoginEndpointRequest true "Create request"
// @Success 201 {object} payload.PasswordLoginEndpointResponse
// @Failure 400 {object} map[string]interface{}
// @Router /admin/management/password-login/endpoints [post]
func (h *PasswordLoginHandler) CreateEndpoint(c *gin.Context) {
	var req payload.CreatePasswordLoginEndpointRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		payload.AbortWithAppError(c, payload.NewValidationAppError(err))
		return
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	endpoint := &model.PasswordLoginEndpoint{
		Name:     req.Name,
		LoginURL: req.LoginURL,
		IsActive: isActive,
	}

	created, err := h.UseCase.CreateEndpoint(c.Request.Context(), endpoint)
	if err != nil {
		if isPasswordLoginValidationError(err) {
			payload.AbortWithAppError(c, payload.NewDetailedAppError(
				http.StatusBadRequest, "validation_failed", err.Error(),
				"Provide a valid absolute http or https login_url and a non-empty name.", nil, err,
			))
			return
		}
		payload.AbortWithAppError(c, payload.NewOperationAppError(http.StatusInternalServerError, "Password login endpoint", "create", err))
		return
	}

	logger.FromGin(c).Info("Password login endpoint created", zap.String("endpoint_id", created.ID))
	c.JSON(http.StatusCreated, payload.FromDomainPasswordLoginEndpoint(created))
}

// GetEndpoint godoc
// @Summary Get password login endpoint
// @Tags Password Login
// @Produce json
// @Param id path string true "Endpoint ID"
// @Success 200 {object} payload.PasswordLoginEndpointResponse
// @Failure 404 {object} map[string]interface{}
// @Router /admin/management/password-login/endpoints/{id} [get]
func (h *PasswordLoginHandler) GetEndpoint(c *gin.Context) {
	id := c.Param("id")
	endpoint, err := h.UseCase.GetEndpoint(c.Request.Context(), id)
	if err != nil {
		payload.AbortWithAppError(c, payload.NewNotFoundAppError("Password login endpoint", err))
		return
	}
	c.JSON(http.StatusOK, payload.FromDomainPasswordLoginEndpoint(endpoint))
}

// ListEndpoints godoc
// @Summary List password login endpoints
// @Tags Password Login
// @Produce json
// @Success 200 {array} payload.PasswordLoginEndpointResponse
// @Router /admin/management/password-login/endpoints [get]
func (h *PasswordLoginHandler) ListEndpoints(c *gin.Context) {
	items, err := h.UseCase.ListEndpoints(c.Request.Context())
	if err != nil {
		payload.AbortWithAppError(c, payload.NewOperationAppError(http.StatusInternalServerError, "Password login endpoints", "list", err))
		return
	}
	c.JSON(http.StatusOK, payload.FromDomainPasswordLoginEndpoints(items))
}

// UpdateEndpoint godoc
// @Summary Update password login endpoint
// @Tags Password Login
// @Accept json
// @Produce json
// @Param id path string true "Endpoint ID"
// @Param request body payload.UpdatePasswordLoginEndpointRequest true "Update request"
// @Success 200 {object} payload.PasswordLoginEndpointResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /admin/management/password-login/endpoints/{id} [put]
func (h *PasswordLoginHandler) UpdateEndpoint(c *gin.Context) {
	id := c.Param("id")

	existing, err := h.UseCase.GetEndpoint(c.Request.Context(), id)
	if err != nil {
		payload.AbortWithAppError(c, payload.NewNotFoundAppError("Password login endpoint", err))
		return
	}

	var req payload.UpdatePasswordLoginEndpointRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		payload.AbortWithAppError(c, payload.NewValidationAppError(err))
		return
	}

	existing.Name = req.Name
	existing.LoginURL = req.LoginURL
	if req.IsActive != nil {
		existing.IsActive = *req.IsActive
	}

	updated, err := h.UseCase.UpdateEndpoint(c.Request.Context(), existing)
	if err != nil {
		if isPasswordLoginValidationError(err) {
			payload.AbortWithAppError(c, payload.NewDetailedAppError(
				http.StatusBadRequest, "validation_failed", err.Error(),
				"Provide a valid absolute http or https login_url and a non-empty name.", nil, err,
			))
			return
		}
		payload.AbortWithAppError(c, payload.NewOperationAppError(http.StatusBadRequest, "Password login endpoint", "update", err))
		return
	}

	logger.FromGin(c).Info("Password login endpoint updated", zap.String("endpoint_id", updated.ID))
	c.JSON(http.StatusOK, payload.FromDomainPasswordLoginEndpoint(updated))
}

// DeleteEndpoint godoc
// @Summary Delete password login endpoint
// @Tags Password Login
// @Param id path string true "Endpoint ID"
// @Success 204
// @Failure 404 {object} map[string]interface{}
// @Router /admin/management/password-login/endpoints/{id} [delete]
func (h *PasswordLoginHandler) DeleteEndpoint(c *gin.Context) {
	id := c.Param("id")
	if err := h.UseCase.DeleteEndpoint(c.Request.Context(), id); err != nil {
		payload.AbortWithAppError(c, payload.NewOperationAppError(http.StatusBadRequest, "Password login endpoint", "delete", err))
		return
	}
	logger.FromGin(c).Info("Password login endpoint deleted", zap.String("endpoint_id", id))
	c.Status(http.StatusNoContent)
}

// ----- Assignment handlers -----

// CreateAssignment godoc
// @Summary Create password login assignment
// @Description Assigns a password login endpoint to a tenant (or globally when tenant_id is omitted/null).
// @Tags Password Login
// @Accept json
// @Produce json
// @Param request body payload.CreatePasswordLoginAssignmentRequest true "Create request"
// @Success 201 {object} payload.PasswordLoginAssignmentResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Router /admin/management/password-login/assignments [post]
func (h *PasswordLoginHandler) CreateAssignment(c *gin.Context) {
	var req payload.CreatePasswordLoginAssignmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		payload.AbortWithAppError(c, payload.NewValidationAppError(err))
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	assignment := &model.PasswordLoginAssignment{
		TenantID:                req.TenantID,
		PasswordLoginEndpointID: req.PasswordLoginEndpointID,
		Enabled:                 enabled,
	}

	created, err := h.UseCase.CreateAssignment(c.Request.Context(), assignment)
	if err != nil {
		if errors.Is(err, usecase.ErrDuplicateActivePasswordAssignment) {
			payload.AbortWithAppError(c, payload.NewConflictAppError("Password login assignment",
				err.Error(), err))
			return
		}
		if errors.Is(err, usecase.ErrPasswordLoginEndpointNotFound) {
			payload.AbortWithAppError(c, payload.NewNotFoundAppError("Password login endpoint", err))
			return
		}
		payload.AbortWithAppError(c, payload.NewOperationAppError(http.StatusInternalServerError, "Password login assignment", "create", err))
		return
	}

	logger.FromGin(c).Info("Password login assignment created", zap.String("assignment_id", created.ID))
	c.JSON(http.StatusCreated, payload.FromDomainPasswordLoginAssignment(created))
}

// GetAssignment godoc
// @Summary Get password login assignment
// @Tags Password Login
// @Produce json
// @Param id path string true "Assignment ID"
// @Success 200 {object} payload.PasswordLoginAssignmentResponse
// @Failure 404 {object} map[string]interface{}
// @Router /admin/management/password-login/assignments/{id} [get]
func (h *PasswordLoginHandler) GetAssignment(c *gin.Context) {
	id := c.Param("id")
	assignment, err := h.UseCase.GetAssignment(c.Request.Context(), id)
	if err != nil {
		payload.AbortWithAppError(c, payload.NewNotFoundAppError("Password login assignment", err))
		return
	}
	c.JSON(http.StatusOK, payload.FromDomainPasswordLoginAssignment(assignment))
}

// ListAssignments godoc
// @Summary List password login assignments
// @Description Lists all assignments. Optionally filter by tenant_id query parameter.
// @Tags Password Login
// @Produce json
// @Param tenant_id query string false "Filter by tenant ID"
// @Success 200 {array} payload.PasswordLoginAssignmentResponse
// @Router /admin/management/password-login/assignments [get]
func (h *PasswordLoginHandler) ListAssignments(c *gin.Context) {
	var tenantID *string
	if t := c.Query("tenant_id"); t != "" {
		tenantID = &t
	}

	items, err := h.UseCase.ListAssignments(c.Request.Context(), tenantID)
	if err != nil {
		payload.AbortWithAppError(c, payload.NewOperationAppError(http.StatusInternalServerError, "Password login assignments", "list", err))
		return
	}
	c.JSON(http.StatusOK, payload.FromDomainPasswordLoginAssignments(items))
}

// UpdateAssignment godoc
// @Summary Update password login assignment
// @Tags Password Login
// @Accept json
// @Produce json
// @Param id path string true "Assignment ID"
// @Param request body payload.UpdatePasswordLoginAssignmentRequest true "Update request"
// @Success 200 {object} payload.PasswordLoginAssignmentResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /admin/management/password-login/assignments/{id} [put]
func (h *PasswordLoginHandler) UpdateAssignment(c *gin.Context) {
	id := c.Param("id")

	existing, err := h.UseCase.GetAssignment(c.Request.Context(), id)
	if err != nil {
		payload.AbortWithAppError(c, payload.NewNotFoundAppError("Password login assignment", err))
		return
	}

	var req payload.UpdatePasswordLoginAssignmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		payload.AbortWithAppError(c, payload.NewValidationAppError(err))
		return
	}

	existing.PasswordLoginEndpointID = req.PasswordLoginEndpointID
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}

	updated, err := h.UseCase.UpdateAssignment(c.Request.Context(), existing)
	if err != nil {
		if errors.Is(err, usecase.ErrPasswordLoginEndpointNotFound) {
			payload.AbortWithAppError(c, payload.NewNotFoundAppError("Password login endpoint", err))
			return
		}
		payload.AbortWithAppError(c, payload.NewOperationAppError(http.StatusBadRequest, "Password login assignment", "update", err))
		return
	}

	logger.FromGin(c).Info("Password login assignment updated", zap.String("assignment_id", updated.ID))
	c.JSON(http.StatusOK, payload.FromDomainPasswordLoginAssignment(updated))
}

// DeleteAssignment godoc
// @Summary Delete password login assignment
// @Tags Password Login
// @Param id path string true "Assignment ID"
// @Success 204
// @Failure 404 {object} map[string]interface{}
// @Router /admin/management/password-login/assignments/{id} [delete]
func (h *PasswordLoginHandler) DeleteAssignment(c *gin.Context) {
	id := c.Param("id")
	if err := h.UseCase.DeleteAssignment(c.Request.Context(), id); err != nil {
		payload.AbortWithAppError(c, payload.NewOperationAppError(http.StatusBadRequest, "Password login assignment", "delete", err))
		return
	}
	logger.FromGin(c).Info("Password login assignment deleted", zap.String("assignment_id", id))
	c.Status(http.StatusNoContent)
}

func isPasswordLoginValidationError(err error) bool {
	return errors.Is(err, usecase.ErrInvalidPasswordLoginURL) ||
		errors.Is(err, usecase.ErrEmptyPasswordLoginName)
}
