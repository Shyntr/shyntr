package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/pkg/consts"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.uber.org/zap"
)

// W3C Trace Context Constants
const (
	Version      = "00"
	FlagsSampled = "01"
)

// TraceContext holds the parsed trace information
type TraceContext struct {
	TraceID  string
	ParentID string // Also known as SpanID for the incoming request
	SpanID   string // The new SpanID for current processing
}

func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use constants from pkg/consts
		tc := extractOrGenerateTraceContext(c.GetHeader(consts.HeaderTraceParent))

		newTraceParent := fmt.Sprintf("%s-%s-%s-%s", Version, tc.TraceID, tc.SpanID, FlagsSampled)

		// Set Context values using constants
		c.Set(consts.ContextKeyTraceID, tc.TraceID)
		c.Set(consts.ContextKeySpanID, tc.SpanID)

		// Set Response Headers using constants
		c.Header(consts.HeaderTraceParent, newTraceParent)
		if state := c.GetHeader(consts.HeaderTraceState); state != "" {
			c.Header(consts.HeaderTraceState, state)
		}

		// Also set X-Request-ID for backward compatibility/logging convenience
		c.Set(consts.ContextKeyRequestID, tc.TraceID)
		c.Header("X-Request-ID", tc.TraceID)

		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		end := time.Now()
		latency := end.Sub(start)

		fields := []zap.Field{
			zap.String("trace_id", tc.TraceID),
			zap.String("span_id", tc.SpanID),
			zap.Int("status", c.Writer.Status()),
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.String("query", query),
			zap.String("ip", c.ClientIP()),
			zap.String("user-agent", c.Request.UserAgent()),
			zap.Duration("latency", latency),
		}

		if len(c.Errors) > 0 {
			for _, e := range c.Errors.Errors() {
				logger.Log.Error(e, fields...)
			}
		} else {
			logger.Log.Info(path, fields...)
		}
	}
}

func extractOrGenerateTraceContext(header string) TraceContext {
	// Simple validation: 00-32hex-16hex-02hex (length 55)
	if len(header) == 55 && strings.Count(header, "-") == 3 {
		parts := strings.Split(header, "-")
		if len(parts) == 4 && parts[0] == Version {
			return TraceContext{
				TraceID:  parts[1],
				ParentID: parts[2],             // Incoming span
				SpanID:   generateRandomHex(8), // Generate new span for our work
			}
		}
	}

	return TraceContext{
		TraceID:  generateRandomHex(16),
		ParentID: "",
		SpanID:   generateRandomHex(8),
	}
}

func generateRandomHex(n int) string {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "0000000000000000"[0 : n*2]
	}
	return hex.EncodeToString(bytes)
}
