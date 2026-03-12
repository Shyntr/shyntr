package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/internal/adapters/http/response"
	"github.com/nevzatcirak/shyntr/internal/application/usecase"
	"github.com/nevzatcirak/shyntr/internal/domain/entity"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
)

type ScopeHandler struct {
	scopeUse usecase.ScopeUseCase
}

func NewScopeHandler(scopeUse usecase.ScopeUseCase) *ScopeHandler {
	return &ScopeHandler{scopeUse: scopeUse}
}

func (h *ScopeHandler) Create(c *gin.Context) {
	tenantID := c.Param("id")
	var req entity.Scope
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid payload", err))
		return
	}
	req.TenantID = tenantID

	scope, err := h.scopeUse.CreateScope(c.Request.Context(), &req, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to create scope", err))
		return
	}

	logger.FromGin(c).Info("Scope created successfully", zap.String("scope_name", scope.Name), zap.String("tenant_id", tenantID))
	c.JSON(http.StatusCreated, scope)
}

func (h *ScopeHandler) List(c *gin.Context) {
	tenantID := c.Param("id")
	scopes, err := h.scopeUse.ListScopes(c.Request.Context(), tenantID)
	if err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to retrieve scopes", err))
		return
	}
	c.JSON(http.StatusOK, scopes)
}

func (h *ScopeHandler) Get(c *gin.Context) {
	tenantID := c.Param("id")
	id := c.Param("scope_id")
	scope, err := h.scopeUse.GetScope(c.Request.Context(), tenantID, id)
	if err != nil {
		c.Error(response.NewAppError(http.StatusNotFound, "Scope not found", err))
		return
	}
	c.JSON(http.StatusOK, scope)
}

func (h *ScopeHandler) Update(c *gin.Context) {
	tenantID := c.Param("id")
	id := c.Param("scope_id")

	var req entity.Scope
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(response.NewAppError(http.StatusBadRequest, "Invalid payload", err))
		return
	}
	req.TenantID = tenantID
	req.ID = id

	if err := h.scopeUse.UpdateScope(c.Request.Context(), &req, c.ClientIP(), c.Request.UserAgent()); err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, "Failed to update scope", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (h *ScopeHandler) Delete(c *gin.Context) {
	tenantID := c.Param("id")
	id := c.Param("scope_id")

	if err := h.scopeUse.DeleteScope(c.Request.Context(), tenantID, id, c.ClientIP(), c.Request.UserAgent()); err != nil {
		c.Error(response.NewAppError(http.StatusInternalServerError, err.Error(), err))
		return
	}
	c.JSON(http.StatusNoContent, nil)
}
