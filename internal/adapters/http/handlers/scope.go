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

type ScopeHandler struct {
	scopeUse usecase.ScopeUseCase
}

func NewScopeHandler(scopeUse usecase.ScopeUseCase) *ScopeHandler {
	return &ScopeHandler{scopeUse: scopeUse}
}

// Create godoc
// @Summary Create Scope
// @Description Creates a new authorization scope for a specific tenant.
// @Tags Scopes
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Tenant ID"
// @Param request body model.Scope true "Scope configuration payload"
// @Success 201 {object} model.Scope "Scope created successfully"
// @Failure 400 {object} payload.AppError "Invalid payload"
// @Failure 500 {object} payload.AppError "Failed to create scope"
// @Router /admin/management/tenants/{id}/scopes [post]
func (h *ScopeHandler) Create(c *gin.Context) {
	tenantID := c.Param("id")
	var req model.Scope
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(payload.NewValidationAppError(err))
		return
	}
	req.TenantID = tenantID
	scope, err := h.scopeUse.CreateScope(c.Request.Context(), &req, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(payload.NewOperationAppError(scopeHTTPStatus(err), "Scope", "create", err))
		return
	}

	logger.FromGin(c).Info("Scope created successfully", zap.String("scope_name", scope.Name), zap.String("tenant_id", tenantID))
	c.JSON(http.StatusCreated, scope)
}

// List godoc
// @Summary List Scopes
// @Description Retrieves all authorization scopes associated with a specific tenant.
// @Tags Scopes
// @Produce json
// @Security BearerAuth
// @Param id path string true "Tenant ID"
// @Success 200 {array} model.Scope "List of scopes"
// @Failure 500 {object} payload.AppError "Failed to retrieve scopes"
// @Router /admin/management/tenants/{id}/scopes [get]
func (h *ScopeHandler) List(c *gin.Context) {
	tenantID := c.Param("id")
	scopes, err := h.scopeUse.ListScopes(c.Request.Context(), tenantID)
	if err != nil {
		c.Error(payload.NewOperationAppError(scopeHTTPStatus(err), "Scopes", "list", err))
		return
	}
	c.JSON(http.StatusOK, scopes)
}

// Get godoc
// @Summary Get Scope
// @Description Retrieves the details of a specific authorization scope within a tenant boundary.
// @Tags Scopes
// @Produce json
// @Security BearerAuth
// @Param id path string true "Tenant ID"
// @Param scope_id path string true "Scope ID"
// @Success 200 {object} model.Scope "Scope details"
// @Failure 404 {object} payload.AppError "Scope not found"
// @Router /admin/management/tenants/{id}/scopes/{scope_id} [get]
func (h *ScopeHandler) Get(c *gin.Context) {
	tenantID := c.Param("id")
	id := c.Param("scope_id")
	scope, err := h.scopeUse.GetScope(c.Request.Context(), tenantID, id)
	if err != nil {
		c.Error(payload.NewNotFoundAppError("Scope", err))
		return
	}
	c.JSON(http.StatusOK, scope)
}

// Update godoc
// @Summary Update Scope
// @Description Updates an existing authorization scope configuration.
// @Tags Scopes
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Tenant ID"
// @Param scope_id path string true "Scope ID"
// @Param request body model.Scope true "Scope update payload"
// @Success 200 {object} map[string]string "status: updated"
// @Failure 400 {object} payload.AppError "Invalid payload"
// @Failure 500 {object} payload.AppError "Failed to update scope"
// @Router /admin/management/tenants/{id}/scopes/{scope_id} [put]
func (h *ScopeHandler) Update(c *gin.Context) {
	tenantID := c.Param("id")
	id := c.Param("scope_id")

	var req model.Scope
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(payload.NewValidationAppError(err))
		return
	}
	req.TenantID = tenantID
	req.ID = id

	if err := h.scopeUse.UpdateScope(c.Request.Context(), &req, c.ClientIP(), c.Request.UserAgent()); err != nil {
		c.Error(payload.NewOperationAppError(scopeHTTPStatus(err), "Scope", "update", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// Delete godoc
// @Summary Delete Scope
// @Description Removes an authorization scope from a specific tenant.
// @Tags Scopes
// @Produce json
// @Security BearerAuth
// @Param id path string true "Tenant ID"
// @Param scope_id path string true "Scope ID"
// @Success 204 "No Content"
// @Failure 500 {object} payload.AppError "Failed to delete scope"
// @Router /admin/management/tenants/{id}/scopes/{scope_id} [delete]
func (h *ScopeHandler) Delete(c *gin.Context) {
	tenantID := c.Param("id")
	id := c.Param("scope_id")

	if err := h.scopeUse.DeleteScope(c.Request.Context(), tenantID, id, c.ClientIP(), c.Request.UserAgent()); err != nil {
		c.Error(payload.NewOperationAppError(scopeHTTPStatus(err), "Scope", "delete", err))
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

func scopeHTTPStatus(err error) int {
	switch {
	case errors.Is(err, usecase.ErrScopeValidation):
		return http.StatusBadRequest
	case errors.Is(err, usecase.ErrScopeConflict):
		return http.StatusConflict
	case errors.Is(err, usecase.ErrSystemScopeRenameDenied):
		return http.StatusBadRequest
	case errors.Is(err, usecase.ErrSystemScopeDeleteDenied):
		return http.StatusBadRequest
	case errors.Is(err, usecase.ErrScopeNotFound):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}
