package middleware

import (
	"time"

	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func StructuredLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		traceID := c.GetHeader("X-Request-Id")
		if traceID == "" {
			traceID = uuid.New().String()
		}
		c.Set("trace_id", traceID)
		c.Header("X-Request-Id", traceID)

		c.Next()

		duration := time.Since(start)
		status := c.Writer.Status()

		logFields := []zap.Field{
			zap.Int("status", status),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("ip", c.ClientIP()),
			zap.Duration("latency", duration),
			zap.String("trace_id", traceID),
		}

		if len(c.Errors) > 0 {
			logFields = append(logFields, zap.String("errors", c.Errors.String()))
			logger.Log.Error("Request failed", logFields...)
		} else if status >= 400 && status < 500 {
			logger.Log.Warn("Client error (4xx)", logFields...)
		} else if status >= 500 {
			logger.Log.Error("Server error (5xx)", logFields...)
		} else {
			logger.Log.Info("Request handled", logFields...)
		}
	}
}
