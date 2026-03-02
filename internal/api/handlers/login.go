package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"gorm.io/gorm"
)

type LoginHandler struct {
	Config *config.Config
	DB     *gorm.DB
}

func NewLoginHandler(cfg *config.Config, db *gorm.DB) *LoginHandler {
	return &LoginHandler{Config: cfg, DB: db}
}

func (h *LoginHandler) GetLoginMethods(c *gin.Context) {
	challenge := c.Query("login_challenge")
	if challenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_login_challenge"})
		return
	}

	var loginReq models.LoginRequest
	if err := h.DB.First(&loginReq, "id = ?", challenge).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid_challenge"})
		return
	}

	if loginReq.Authenticated {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":       "already_authenticated",
			"redirect_to": fmt.Sprintf("%s&login_verifier=%s", loginReq.RequestURL, loginReq.ID),
		})
		return
	}

	tenantID := loginReq.TenantID

	var samlConns []models.SAMLConnection
	h.DB.Where("tenant_id = ? AND active = ?", tenantID, true).Find(&samlConns)

	var oidcConns []models.OIDCConnection
	h.DB.Where("tenant_id = ? AND active = ?", tenantID, true).Find(&oidcConns)

	type AuthMethod struct {
		ID       string `json:"id"`
		Type     string `json:"type"` // "saml", "oidc", "password"
		Name     string `json:"name"`
		LogoURL  string `json:"logo_url,omitempty"`
		LoginURL string `json:"login_url"`
	}

	methods := []AuthMethod{}

	if tenantID == "default" {
		methods = append(methods, AuthMethod{
			ID:   "basic-auth",
			Type: "password",
			Name: "Username & Password",
		})
	}

	for _, conn := range samlConns {
		methods = append(methods, AuthMethod{
			ID:       conn.ID,
			Type:     "saml",
			Name:     conn.Name,
			LoginURL: h.Config.BaseIssuerURL + "/t/" + tenantID + "/saml/login/" + conn.ID + "?login_challenge=" + challenge,
		})
	}

	for _, conn := range oidcConns {
		methods = append(methods, AuthMethod{
			ID:       conn.ID,
			Type:     "oidc",
			Name:     conn.Name,
			LoginURL: h.Config.BaseIssuerURL + "/t/" + tenantID + "/oidc/login/" + conn.ID + "?login_challenge=" + challenge,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"challenge": loginReq.ID,
		"tenant_id": tenantID,
		"methods":   methods,
	})
}
