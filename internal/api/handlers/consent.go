package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type ConsentHandler struct{}

func NewConsentHandler() *ConsentHandler {
	return &ConsentHandler{}
}

// ShowConsent displays the consent UI.
func (h *ConsentHandler) ShowConsent(c *gin.Context) {
	clientID := c.Query("client_id")
	scopes := c.Query("scopes")
	returnTo := c.Query("return_to")

	csrfToken, _ := c.Get("csrf_token")

	c.JSON(200, gin.H{
		"message":    "Consent Required",
		"client_id":  clientID,
		"scopes":     scopes,
		"action":     "POST /consent",
		"return_to":  returnTo,
		"csrf_token": csrfToken,
		"info":       "This app wants to access your profile. Do you agree?",
	})
}

// SubmitConsent handles the user's approval.
func (h *ConsentHandler) SubmitConsent(c *gin.Context) {
	var req struct {
		ReturnTo string `json:"return_to"`
		Action   string `json:"action"` // "allow" or "deny"
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Action == "allow" {
		separator := "?"
		// Simple logic to check if URL already has parameters
		if strings.Contains(req.ReturnTo, "?") {
			separator = "&"
		}

		redirectURL := fmt.Sprintf("%s%sconsent_verifier=approved", req.ReturnTo, separator)
		c.JSON(200, gin.H{"status": "success", "redirect_to": redirectURL})
	} else {
		c.JSON(200, gin.H{"status": "denied", "message": "Consent denied"})
	}
}
