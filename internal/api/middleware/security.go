package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
)

// SecurityHeaders adds standard security headers to every response.
// Helps prevent XSS, clickjacking, and enforces HTTPS.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Strict-Transport-Security: Force HTTPS for 1 year (production only)
		// c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// X-Content-Type-Options: Prevent MIME-sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// X-Frame-Options: Deny to prevent clickjacking (allow framing only by same origin if needed)
		c.Header("X-Frame-Options", "DENY")

		// X-XSS-Protection: Enable XSS filtering
		c.Header("X-XSS-Protection", "1; mode=block")

		// Content-Security-Policy: Restrict sources for scripts, styles, etc.
		// Adjust this based on your frontend needs.
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;")

		c.Next()
	}
}

// CSRFMiddleware generates a CSRF token for GET requests and validates it for POST/PUT/DELETE.
// This is a simplified Double Submit Cookie pattern.
func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Generate Token if not present
		token, err := c.Cookie("csrf_token")
		if err != nil || token == "" {
			bytes := make([]byte, 32)
			if _, err := rand.Read(bytes); err == nil {
				token = hex.EncodeToString(bytes)
				// Set HTTP-only to false so frontend JS can read it if necessary,
				// but Double Submit usually requires reading the cookie to send header.
				// For strict security, we use HttpOnly=false for the CSRF cookie so JS can read it and send it in a header.
				c.SetCookie("csrf_token", token, 3600, "/", "", false, false)
			}
		}

		// 2. Set the token in the context so handlers can send it to the view
		c.Set("csrf_token", token)

		// 3. Validate Token for state-changing methods
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "DELETE" {
			// Read token from Header (X-CSRF-Token) or Form value
			requestToken := c.GetHeader("X-CSRF-Token")
			if requestToken == "" {
				requestToken = c.PostForm("csrf_token")
			}

			if requestToken == "" || requestToken != token {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "CSRF token mismatch"})
				return
			}
		}

		c.Next()
	}
}
