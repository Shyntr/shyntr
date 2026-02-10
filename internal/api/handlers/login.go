package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/config"
	"github.com/nevzatcirak/shyntr/internal/data/models"
	"github.com/nevzatcirak/shyntr/pkg/crypto"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type LoginHandler struct {
	DB     *gorm.DB
	Config *config.Config
}

func NewLoginHandler(db *gorm.DB) *LoginHandler {
	return &LoginHandler{
		DB:     db,
		Config: config.LoadConfig(),
	}
}

// LoginRequest defines the expected payload with validation tags
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	ReturnTo string `json:"return_to"`
	TenantID string `json:"tenant_id"`
}

func (h *LoginHandler) ShowLogin(c *gin.Context) {
	returnTo := c.Query("return_to")
	csrfToken, _ := c.Get("csrf_token")

	c.JSON(200, gin.H{
		"message":    "Shyntr Login",
		"action":     "POST /login",
		"return_to":  returnTo,
		"csrf_token": csrfToken,
		"fields":     []string{"email", "password"},
	})
}

func (h *LoginHandler) SubmitLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.Warn("Invalid login attempt", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
		return
	}

	if req.TenantID == "" {
		req.TenantID = h.Config.DefaultTenantID
	}

	var user models.User
	if err := h.DB.Where("email = ? AND tenant_id = ?", req.Email, req.TenantID).First(&user).Error; err != nil {
		// Use generic error message to prevent user enumeration
		logger.Log.Warn("Login failed: User not found", zap.String("email", req.Email))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	if !crypto.CheckPasswordHash(req.Password, user.PasswordHash) {
		logger.Log.Warn("Login failed: Invalid password", zap.String("email", req.Email))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	c.SetCookie(
		"shyntr_session",
		user.ID,
		3600,
		"/",
		"",
		h.Config.CookieSecure,
		true,
	)

	logger.Log.Info("User logged in successfully", zap.String("user_id", user.ID))

	if req.ReturnTo != "" {
		c.JSON(200, gin.H{"status": "success", "redirect_to": req.ReturnTo})
	} else {
		c.JSON(200, gin.H{"status": "success", "message": "Logged in"})
	}
}
