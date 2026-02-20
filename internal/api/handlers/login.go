package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"gorm.io/gorm"
)

type LoginHandler struct {
	DB *gorm.DB
}

func NewLoginHandler(db *gorm.DB) *LoginHandler {
	return &LoginHandler{DB: db}
}

func (h *LoginHandler) ShowLogin(c *gin.Context) {
	challenge := c.Query("login_challenge")
	if challenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_login_challenge"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":         "Please render login UI",
		"login_challenge": challenge,
		"api_url":         "/auth/methods?login_challenge=" + challenge,
	})
}

func (h *LoginHandler) SubmitLogin(c *gin.Context) {
	var req struct {
		LoginChallenge string `json:"login_challenge"`
		Username       string `json:"username"`
		Password       string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	var loginReq models.LoginRequest
	if err := h.DB.First(&loginReq, "id = ?", req.LoginChallenge).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid_login_challenge"})
		return
	}

	if loginReq.TenantID != "default" {
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "local_login_disabled",
			"message": "This tenant only supports SSO (SAML/OIDC) authentication.",
		})
		return
	}

	if req.Username == "admin" && req.Password == "password" {
		loginReq.Authenticated = true
		loginReq.Subject = "user-admin-123"
		loginReq.UpdatedAt = time.Now()

		userCtx := map[string]string{"username": "admin", "role": "admin"}
		ctxBytes, _ := json.Marshal(userCtx)
		loginReq.Context = ctxBytes

		h.DB.Save(&loginReq)

		redirectURL := fmt.Sprintf("%s&login_verifier=%s", loginReq.RequestURL, loginReq.ID)
		c.JSON(http.StatusOK, gin.H{"redirect_to": redirectURL})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
	}
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
			LoginURL: "/saml/login/" + conn.ID + "?login_challenge=" + challenge,
		})
	}

	for _, conn := range oidcConns {
		methods = append(methods, AuthMethod{
			ID:       conn.ID,
			Type:     "oidc",
			Name:     conn.Name,
			LoginURL: "/t/" + tenantID + "/oidc/login/" + conn.ID + "?login_challenge=" + challenge,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"challenge": loginReq.ID,
		"tenant_id": tenantID,
		"methods":   methods,
	})
}
