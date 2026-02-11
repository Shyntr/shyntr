package middleware

import (
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/pkg/consts"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"github.com/nevzatcirak/shyntr/pkg/utils"
	"go.uber.org/zap"
)

const (
	Version      = "00"
	FlagsSampled = "01"
)

type TraceContext struct {
	TraceID  string
	ParentID string
	SpanID   string
}

func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		tc := extractOrGenerateTraceContext(c.GetHeader(consts.HeaderTraceParent))

		newTraceParent := fmt.Sprintf("%s-%s-%s-%s", Version, tc.TraceID, tc.SpanID, FlagsSampled)

		c.Set(consts.ContextKeyTraceID, tc.TraceID)
		c.Set(consts.ContextKeySpanID, tc.SpanID)

		c.Header(consts.HeaderTraceParent, newTraceParent)
		if state := c.GetHeader(consts.HeaderTraceState); state != "" {
			c.Header(consts.HeaderTraceState, state)
		}

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
	if len(header) == 55 && strings.Count(header, "-") == 3 {
		parts := strings.Split(header, "-")
		if len(parts) == 4 && parts[0] == Version {
			return TraceContext{
				TraceID:  parts[1],
				ParentID: parts[2],
				SpanID:   utils.GenerateRandomHexOrPanic(8),
			}
		}
	}

	return TraceContext{
		TraceID:  utils.GenerateRandomHexOrPanic(16),
		ParentID: "",
		SpanID:   utils.GenerateRandomHexOrPanic(8),
	}
}
