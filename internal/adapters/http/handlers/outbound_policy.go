package handlers

import (
	"net/http"

	"github.com/Shyntr/shyntr/internal/adapters/http/payload"
	"github.com/Shyntr/shyntr/internal/application/usecase"
	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type OutboundPolicyHandler struct {
	UseCase usecase.OutboundPolicyUseCase
}

func NewOutboundPolicyHandler(uc usecase.OutboundPolicyUseCase) *OutboundPolicyHandler {
	return &OutboundPolicyHandler{UseCase: uc}
}

// Create godoc
// @Summary Create outbound policy
// @Description Creates a new outbound security policy for global or tenant-specific outbound HTTP controls.
// @Tags Outbound Policies
// @Accept json
// @Produce json
// @Param request body payload.CreateOutboundPolicyRequest true "Create outbound policy request"
// @Success 201 {object} payload.OutboundPolicyResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /admin/management/outbound-policies [post]
func (h *OutboundPolicyHandler) Create(c *gin.Context) {
	var req payload.CreateOutboundPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		payload.AbortWithAppError(c, payload.NewValidationAppError(err))
		return
	}

	policy, err := h.UseCase.CreatePolicy(c.Request.Context(), req.ToDomain(), c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		payload.AbortWithAppError(c, payload.NewOperationAppError(http.StatusBadRequest, "Outbound policy", "create", err))
		return
	}

	logger.FromGin(c).Info("Outbound policy created", zap.String("policy_id", policy.ID))
	c.JSON(http.StatusCreated, payload.FromDomainOutboundPolicy(policy))
}

// Get godoc
// @Summary Get outbound policy
// @Description Returns a single outbound policy by id.
// @Tags Outbound Policies
// @Accept json
// @Produce json
// @Param id path string true "Policy ID"
// @Success 200 {object} payload.OutboundPolicyResponse
// @Failure 404 {object} map[string]interface{}
// @Router /admin/management/outbound-policies/{id} [get]
func (h *OutboundPolicyHandler) Get(c *gin.Context) {
	id := c.Param("id")

	policy, err := h.UseCase.GetPolicy(c.Request.Context(), id)
	if err != nil {
		payload.AbortWithAppError(c, payload.NewNotFoundAppError("Outbound policy", err))
		return
	}

	c.JSON(http.StatusOK, payload.FromDomainOutboundPolicy(policy))
}

// List godoc
// @Summary List outbound policies
// @Description Lists outbound policies. If tenant_id is provided, returns tenant and global policies.
// @Tags Outbound Policies
// @Accept json
// @Produce json
// @Param tenant_id query string false "Tenant ID"
// @Success 200 {array} payload.OutboundPolicyResponse
// @Failure 500 {object} map[string]interface{}
// @Router /admin/management/outbound-policies [get]
func (h *OutboundPolicyHandler) List(c *gin.Context) {
	tenantID := c.Query("tenant_id")

	items, err := h.UseCase.ListPolicies(c.Request.Context(), tenantID)
	if err != nil {
		payload.AbortWithAppError(c, payload.NewOperationAppError(http.StatusBadRequest, "Outbound policies", "list", err))
		return
	}

	c.JSON(http.StatusOK, payload.FromDomainOutboundPolicies(items))
}

// Update godoc
// @Summary Update outbound policy
// @Description Updates an existing outbound policy by id.
// @Tags Outbound Policies
// @Accept json
// @Produce json
// @Param id path string true "Policy ID"
// @Param request body payload.UpdateOutboundPolicyRequest true "Update outbound policy request"
// @Success 200 {object} payload.OutboundPolicyResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /admin/management/outbound-policies/{id} [put]
func (h *OutboundPolicyHandler) Update(c *gin.Context) {
	id := c.Param("id")

	existing, err := h.UseCase.GetPolicy(c.Request.Context(), id)
	if err != nil {
		payload.AbortWithAppError(c, payload.NewNotFoundAppError("Outbound policy", err))
		return
	}

	var req payload.UpdateOutboundPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		payload.AbortWithAppError(c, payload.NewValidationAppError(err))
		return
	}

	payload.ApplyOutboundPolicyUpdate(existing, &req)

	updated, err := h.UseCase.UpdatePolicy(c.Request.Context(), existing, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		payload.AbortWithAppError(c, payload.NewOperationAppError(http.StatusBadRequest, "Outbound policy", "update", err))
		return
	}

	logger.FromGin(c).Info("Outbound policy updated", zap.String("policy_id", updated.ID))
	c.JSON(http.StatusOK, payload.FromDomainOutboundPolicy(updated))
}

// Delete godoc
// @Summary Delete outbound policy
// @Description Deletes an outbound policy by id.
// @Tags Outbound Policies
// @Accept json
// @Produce json
// @Param id path string true "Policy ID"
// @Success 204
// @Failure 500 {object} map[string]interface{}
// @Router /admin/management/outbound-policies/{id} [delete]
func (h *OutboundPolicyHandler) Delete(c *gin.Context) {
	id := c.Param("id")

	if err := h.UseCase.DeletePolicy(c.Request.Context(), id, c.ClientIP(), c.Request.UserAgent()); err != nil {
		payload.AbortWithAppError(c, payload.NewOperationAppError(http.StatusBadRequest, "Outbound policy", "delete", err))
		return
	}

	logger.FromGin(c).Info("Outbound policy deleted", zap.String("policy_id", id))
	c.Status(http.StatusNoContent)
}
