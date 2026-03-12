package middleware

import (
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
