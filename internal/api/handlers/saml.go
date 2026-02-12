package handlers

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/internal/core/saml"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type SAMLHandler struct {
	Service *saml.Service
	DB      *gorm.DB
}

func NewSAMLHandler(s *saml.Service, db *gorm.DB) *SAMLHandler {
	return &SAMLHandler{Service: s, DB: db}
}

func (h *SAMLHandler) SPMetadata(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Service.Config.DefaultTenantID
	}

	sp, err := h.Service.BuildServiceProvider(c.Request.Context(), tenantID, nil)
	if err != nil {
		logger.Log.Error("Failed to initialize SP", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "saml_initialization_failed"})
		return
	}

	metaDesc := sp.Metadata()

	c.Header("Content-Type", "application/xml")
	if err := xml.NewEncoder(c.Writer).Encode(metaDesc); err != nil {
		logger.Log.Error("Failed to write metadata XML", zap.Error(err))
	}
}

func (h *SAMLHandler) Login(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Service.Config.DefaultTenantID
	}
	connectionID := c.Param("connection_id")
	loginChallenge := c.Query("login_challenge")

	if loginChallenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_login_challenge"})
		return
	}

	var loginReq models.LoginRequest
	if err := h.DB.First(&loginReq, "id = ?", loginChallenge).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "login_request_not_found"})
		return
	}

	redirectURL, requestID, err := h.Service.InitiateSSO(c.Request.Context(), tenantID, connectionID, loginChallenge)
	if err != nil {
		logger.Log.Error("Failed to initiate SAML SSO", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sso_init_failed", "details": err.Error()})
		return
	}

	if requestID != "" {
		loginReq.SAMLRequestID = requestID
		h.DB.Save(&loginReq)
	}

	c.Redirect(http.StatusFound, redirectURL)
}

func (h *SAMLHandler) ACS(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Service.Config.DefaultTenantID
	}

	relayState := c.PostForm("RelayState")
	if relayState == "" {
		logger.Log.Warn("Missing RelayState in SAML Response")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing_relay_state"})
		return
	}

	var loginReq models.LoginRequest
	if err := h.DB.First(&loginReq, "id = ?", relayState).Error; err != nil {
		logger.Log.Warn("Invalid RelayState (LoginRequest not found)", zap.String("challenge", relayState))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid_session"})
		return
	}

	assertion, _, err := h.Service.HandleACS(c.Request.Context(), tenantID, c.Request, loginReq.SAMLRequestID)
	if err != nil {
		logger.Log.Warn("SAML ACS Validation Failed", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid_saml_response", "details": err.Error()})
		return
	}

	rawAttributes := make(map[string]interface{})
	for _, statement := range assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			if len(attr.Values) > 1 {
				vals := make([]string, len(attr.Values))
				for i, v := range attr.Values {
					vals[i] = v.Value
				}
				rawAttributes[attr.Name] = vals
			} else if len(attr.Values) == 1 {
				rawAttributes[attr.Name] = attr.Values[0].Value
			}
		}
	}

	issuer := assertion.Issuer.Value
	var conn models.SAMLConnection
	if err := h.DB.Select("attribute_mapping").Where("tenant_id = ? AND idp_entity_id = ?", tenantID, issuer).First(&conn).Error; err != nil {
		logger.Log.Warn("Connection not found for mapping, using raw attributes", zap.String("issuer", issuer))
	}

	finalAttributes := make(map[string]interface{})
	mapping := make(map[string]string)

	if len(conn.AttributeMapping) > 0 {
		_ = json.Unmarshal(conn.AttributeMapping, &mapping)
	}

	for oidcKey, samlKey := range mapping {
		if val, ok := rawAttributes[samlKey]; ok {
			finalAttributes[oidcKey] = val
		}
	}

	if len(finalAttributes) == 0 {
		finalAttributes = rawAttributes
	}

	subject := assertion.Subject.NameID.Value
	finalAttributes["email"] = subject
	finalAttributes["sub"] = subject
	finalAttributes["source"] = "saml"
	finalAttributes["issuer"] = issuer

	contextBytes, _ := json.Marshal(finalAttributes)
	loginReq.Authenticated = true
	loginReq.Subject = subject
	loginReq.Context = contextBytes
	loginReq.UpdatedAt = time.Now()

	if err := h.DB.Save(&loginReq).Error; err != nil {
		logger.Log.Error("Failed to update login request", zap.Error(err))
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	redirectURL := fmt.Sprintf("%s&login_verifier=%s", loginReq.RequestURL, loginReq.ID)
	c.Redirect(http.StatusFound, redirectURL)
}

func (h *SAMLHandler) IDPMetadata(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Service.Config.DefaultTenantID
	}

	idp, err := h.Service.GetIdentityProvider(c.Request.Context(), tenantID)
	if err != nil {
		logger.Log.Error("Failed to initialize IdP", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "idp_init_failed"})
		return
	}

	metaDesc := idp.Metadata()

	c.Header("Content-Type", "application/xml")
	if err := xml.NewEncoder(c.Writer).Encode(metaDesc); err != nil {
		logger.Log.Error("Failed to write metadata XML", zap.Error(err))
	}
}

func (h *SAMLHandler) IDPSSO(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		tenantID = h.Service.Config.DefaultTenantID
	}

	if loginVerifier := c.Query("login_verifier"); loginVerifier != "" {
		h.handleIDPPostLogin(c, tenantID, loginVerifier)
		return
	}

	authReq, err := h.Service.ParseAuthnRequest(c.Request.Context(), tenantID, c.Request)
	if err != nil {
		logger.Log.Error("Failed to parse SAML AuthnRequest", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_saml_request", "details": err.Error()})
		return
	}

	var spClient models.SAMLClient
	if err := h.DB.Where("entity_id = ? AND tenant_id = ?", authReq.Issuer.Value, tenantID).First(&spClient).Error; err != nil {
		logger.Log.Warn("Unknown SP EntityID", zap.String("entity_id", authReq.Issuer.Value))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "unknown_service_provider"})
		return
	}

	rawSAMLRequest := c.Query("SAMLRequest")
	if rawSAMLRequest == "" {
		rawSAMLRequest = c.PostForm("SAMLRequest")
	}

	ctxData := map[string]interface{}{
		"saml_request":    rawSAMLRequest,
		"relay_state_raw": c.Query("RelayState"),
		"sp_entity_id":    spClient.EntityID,
		"protocol":        "saml",
	}
	if ctxData["relay_state_raw"] == "" {
		ctxData["relay_state_raw"] = c.PostForm("RelayState")
	}

	ctxBytes, _ := json.Marshal(ctxData)

	loginReq := models.LoginRequest{
		ID:         fmt.Sprintf("req-%d", time.Now().UnixNano()),
		TenantID:   tenantID,
		RequestURL: fmt.Sprintf("%s/t/%s/saml/idp/sso", h.Service.Config.BaseIssuerURL, tenantID),
		ClientID:   spClient.ID,
		ClientIP:   c.ClientIP(),
		Context:    ctxBytes,
		Active:     true,
		CreatedAt:  time.Now(),
	}

	if err := h.DB.Create(&loginReq).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}

	redirectURL := fmt.Sprintf("/auth/login?login_challenge=%s", loginReq.ID)
	c.Redirect(http.StatusFound, redirectURL)
}

func (h *SAMLHandler) handleIDPPostLogin(c *gin.Context, tenantID, verifier string) {
	var loginReq models.LoginRequest
	if err := h.DB.First(&loginReq, "id = ?", verifier).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid_verifier"})
		return
	}

	if !loginReq.Authenticated {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication_pending"})
		return
	}

	var ctxData map[string]interface{}
	if err := json.Unmarshal(loginReq.Context, &ctxData); err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "corrupt_session_context"})
		return
	}

	rawSAML := ctxData["saml_request"].(string)
	relayState, _ := ctxData["relay_state_raw"].(string)

	mockURL, _ := http.NewRequest("GET", fmt.Sprintf("?SAMLRequest=%s", url.QueryEscape(rawSAML)), nil)

	authReq, err := h.Service.ParseAuthnRequest(c.Request.Context(), tenantID, mockURL)
	if err != nil {
		logger.Log.Error("Failed to re-parse SAML Request", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_original_request"})
		return
	}

	var spClient models.SAMLClient
	if err := h.DB.Where("entity_id = ?", authReq.Issuer.Value).First(&spClient).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "sp_not_found"})
		return
	}

	userAttrs := map[string]interface{}{
		"sub":   loginReq.Subject,
		"email": loginReq.Subject,
	}

	htmlResponse, err := h.Service.GenerateSAMLResponse(c.Request.Context(), tenantID, authReq, &spClient, userAttrs, relayState)
	if err != nil {
		logger.Log.Error("Failed to generate SAML Response", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "response_generation_failed"})
		return
	}

	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, htmlResponse)
}
