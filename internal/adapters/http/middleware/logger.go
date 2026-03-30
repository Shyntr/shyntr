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

		if protocol, exists := c.Get("protocol"); exists {
			if protocolStr, ok := protocol.(string); ok && protocolStr != "" {
				logFields = append(logFields, zap.String("protocol", protocolStr))
			}
		}
		if tenantID, exists := c.Get("tenant_id"); exists {
			if tenantIDStr, ok := tenantID.(string); ok && tenantIDStr != "" {
				logFields = append(logFields, zap.String("tenant_id", tenantIDStr))
			}
		}
		if connectionID, exists := c.Get("connection_id"); exists {
			if connectionIDStr, ok := connectionID.(string); ok && connectionIDStr != "" {
				logFields = append(logFields, zap.String("connection_id", connectionIDStr))
			}
		}
		if errorCode, exists := c.Get("error_code"); exists {
			if errorCodeStr, ok := errorCode.(string); ok && errorCodeStr != "" {
				logFields = append(logFields, zap.String("error_code", errorCodeStr))
			}
		}
		if failureStage, exists := c.Get("failure_stage"); exists {
			if failureStageStr, ok := failureStage.(string); ok && failureStageStr != "" {
				logFields = append(logFields, zap.String("failure_stage", failureStageStr))
			}
		}

		if len(c.Errors) > 0 {
			logFields = append(logFields, zap.String("errors", c.Errors.String()))
			logger.Log.Debug("Request failed", logFields...)
		} else if status >= 400 && status < 500 {
			logger.Log.Debug("Client error (4xx)", logFields...)
		} else if status >= 500 {
			logger.Log.Debug("Server error (5xx)", logFields...)
		} else {
			logger.Log.Debug("Request handled", logFields...)
		}
	}
}
