package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/config"
	"gorm.io/gorm"
)

// LoginHandler is now just a Mock/Test Harness UI.
// In production, the "External Login URL" will point to your real frontend application.
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

// LoginRequest defines the payload our Mock UI sends (to itself).
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	ReturnTo string `json:"return_to"`
}

func (h *LoginHandler) ShowLogin(c *gin.Context) {
	returnTo := c.Query("return_to")
	csrfToken, _ := c.Get("csrf_token")

	c.JSON(200, gin.H{
		"message":    "Shyntr Broker Login (Test UI)",
		"action":     "POST /auth/login",
		"return_to":  returnTo,
		"csrf_token": csrfToken,
		"note":       "Enter any email/password. This is a mock UI.",
	})
}

func (h *LoginHandler) SubmitLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// MOCK: We accept any user for testing.
	// In a real scenario, this UI would verify creds against LDAP/Google/DB.

	// We simulate a successful login by calling Shyntr Admin API internally?
	// OR we just tell the user to make the PUT request via Postman/Curl.

	// For simplicity in this demo:
	c.JSON(200, gin.H{
		"status":  "simulated_success",
		"message": "User credentials valid (Mock). Now perform PUT /admin/login/accept with this subject.",
		"subject": req.Email,
		"context": gin.H{
			"email": req.Email,
			"name":  "Mock User",
			"role":  "admin",
		},
		"next_step": "PUT /admin/login/accept?login_challenge=... with body JSON",
	})
}
