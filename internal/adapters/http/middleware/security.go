package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// SecurityHeaders adds standard security headers to every response.
// Applies protocol-aware defaults so browser-based federation flows are not
// broken by a single restrictive CSP for every endpoint.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		if isHTTPSRequest(c) {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()")

		if shouldDenyFraming(c.Request.URL.Path) {
			c.Header("X-Frame-Options", "DENY")
		} else {
			c.Header("X-Frame-Options", "SAMEORIGIN")
		}

		c.Header("Content-Security-Policy", contentSecurityPolicyForPath(c.Request.URL.Path))

		c.Next()
	}
}

func isHTTPSRequest(c *gin.Context) bool {
	if c.Request.TLS != nil {
		return true
	}

	forwardedProto := strings.ToLower(strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")))
	return forwardedProto == "https"
}

func shouldDenyFraming(path string) bool {
	if isSAMLHTMLResponsePath(path) {
		return false
	}

	return true
}

func contentSecurityPolicyForPath(path string) string {
	if isSAMLHTMLResponsePath(path) || isProtocolBrowserEndpoint(path) {
		return strings.Join([]string{
			"default-src 'self'",
			"base-uri 'none'",
			"frame-ancestors 'none'",
			"object-src 'none'",
			"img-src 'self' data:",
			"style-src 'self' 'unsafe-inline'",
			"script-src 'self' 'unsafe-inline'",
			"form-action 'self' https:",
		}, "; ")
	}

	return strings.Join([]string{
		"default-src 'none'",
		"base-uri 'none'",
		"frame-ancestors 'none'",
		"object-src 'none'",
		"img-src 'self' data:",
		"style-src 'self' 'unsafe-inline'",
		"form-action 'self'",
	}, "; ")
}

func isSAMLHTMLResponsePath(path string) bool {
	switch {
	case strings.HasSuffix(path, "/saml/idp/sso"):
		return true
	case strings.HasSuffix(path, "/saml/idp/slo"):
		return true
	case strings.HasSuffix(path, "/saml/resume"):
		return true
	default:
		return false
	}
}

func isProtocolBrowserEndpoint(path string) bool {
	switch {
	case strings.HasSuffix(path, "/oauth2/auth"):
		return true
	case strings.HasSuffix(path, "/oauth2/logout"):
		return true
	case strings.HasSuffix(path, "/oidc/callback"):
		return true
	case strings.HasSuffix(path, "/oidc/login"):
		return true
	case strings.Contains(path, "/oidc/login/"):
		return true
	case strings.HasSuffix(path, "/saml/sp/acs"):
		return true
	case strings.HasSuffix(path, "/saml/sp/slo"):
		return true
	case strings.HasSuffix(path, "/auth/methods"):
		return true
	default:
		return false
	}
}
