package logger

import (
	"os"
	"sync"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	Log  *zap.Logger
	once sync.Once
)

func InitLogger(level string) {
	once.Do(func() {
		env := os.Getenv("GO_ENV")

		logLevel, err := zapcore.ParseLevel(level)
		if err != nil {
			logLevel = zapcore.InfoLevel
		}

		var config zap.Config
		if env == "production" {
			config = zap.NewProductionConfig()
			config.EncoderConfig.TimeKey = "timestamp"
			config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		} else {
			config = zap.NewDevelopmentConfig()
			config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		}

		config.Level = zap.NewAtomicLevelAt(logLevel)

		Log, err = config.Build()
		if err != nil {
			panic("Failed to initialize logger: " + err.Error())
		}
	})
}

func Sync() {
	if Log != nil {
		_ = Log.Sync()
	}
}

func FromGin(c *gin.Context) *zap.Logger {
	if c == nil || Log == nil {
		return Log
	}

	log := Log

	log = log.With(
		zap.String("ip", c.ClientIP()),
		zap.String("method", c.Request.Method),
		zap.String("path", c.Request.URL.Path),
	)

	span := trace.SpanFromContext(c.Request.Context())
	if span.SpanContext().HasTraceID() {
		log = log.With(zap.String("trace_id", span.SpanContext().TraceID().String()))
	}
	if span.SpanContext().HasSpanID() {
		log = log.With(zap.String("span_id", span.SpanContext().SpanID().String()))
	}

	if url, exists := c.Get("url"); exists {
		log = log.With(zap.String("url", url.(string)))
	}
	if verifier, exists := c.Get("verifier"); exists {
		log = log.With(zap.String("verifier", verifier.(string)))
	}
	if clientID, exists := c.Get("client_id"); exists {
		log = log.With(zap.String("client_id", clientID.(string)))
	}
	if tenantID, exists := c.Get("tenant_id"); exists {
		log = log.With(zap.String("tenant_id", tenantID.(string)))
	}
	if entityID, exists := c.Get("entity_id"); exists {
		log = log.With(zap.String("entity_id", entityID.(string)))
	}
	if targetTenantID, exists := c.Get("target_tenant_id"); exists {
		log = log.With(zap.String("target_tenant_id", targetTenantID.(string)))
	}
	if protocol, exists := c.Get("protocol"); exists {
		log = log.With(zap.String("protocol", protocol.(string)))
	}

	if sub, exists := c.Get("user_sub"); exists {
		log = log.With(zap.String("sub", sub.(string)))
	}
	if email, exists := c.Get("user_email"); exists {
		log = log.With(zap.String("email", email.(string)))
	}

	return log
}
