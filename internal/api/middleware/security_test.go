package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/internal/api/middleware"
	"github.com/stretchr/testify/assert"
)

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.CSRFMiddleware())

	r.Any("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "success"})
	})
	return r
}

func TestSecurityHeaders(t *testing.T) {
	r := setupTestRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)

	r.ServeHTTP(w, req)

	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "default-src 'self'")
}

func TestCSRFMiddleware(t *testing.T) {
	r := setupTestRouter()

	t.Run("GET Request generates CSRF token", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		cookies := w.Result().Cookies()
		var csrfCookie string
		for _, c := range cookies {
			if c.Name == "csrf_token" {
				csrfCookie = c.Value
			}
		}
		assert.NotEmpty(t, csrfCookie, "CSRF cookie should be generated on GET request")
	})

	t.Run("POST Request without CSRF token is rejected", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/test", nil)

		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "valid-token-123"})

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "CSRF token mismatch")
	})

	t.Run("POST Request with valid CSRF token in Header passes", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/test", nil)

		validToken := "valid-token-123"
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: validToken})
		req.Header.Set("X-CSRF-Token", validToken)

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("POST Request with valid CSRF token in Form passes", func(t *testing.T) {
		w := httptest.NewRecorder()

		validToken := "valid-token-123"
		form := url.Values{}
		form.Add("csrf_token", validToken)

		req, _ := http.NewRequest("POST", "/test", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: validToken})

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("POST Request with mismatched token is rejected", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/test", nil)

		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "valid-token-123"})
		req.Header.Set("X-CSRF-Token", "hacker-token-999")

		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}
