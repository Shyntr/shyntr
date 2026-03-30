package logger

import (
	"os"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
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
			config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
			config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		}

		config.Level = zap.NewAtomicLevelAt(logLevel)

		Log, err = config.Build(zap.AddStacktrace(zap.ErrorLevel))
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
	} else if traceID, exists := c.Get("trace_id"); exists {
		if traceIDStr, ok := traceID.(string); ok && traceIDStr != "" {
			log = log.With(zap.String("trace_id", traceIDStr))
		}
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
	if errorCode, exists := c.Get("error_code"); exists {
		log = log.With(zap.String("error_code", errorCode.(string)))
	}
	if failureStage, exists := c.Get("failure_stage"); exists {
		log = log.With(zap.String("failure_stage", failureStage.(string)))
	}
	if connectionID, exists := c.Get("connection_id"); exists {
		log = log.With(zap.String("connection_id", connectionID.(string)))
	}

	if sub, exists := c.Get("user_sub"); exists {
		log = log.With(zap.String("sub", sub.(string)))
	}
	if email, exists := c.Get("user_email"); exists {
		log = log.With(zap.String("email", email.(string)))
	}

	return log
}

func LogFositeError(c *gin.Context, err error, contextMsg string) {
	if err == nil {
		return
	}

	rfcErr := fosite.ErrorToRFC6749Error(err)

	if rfcErr.CodeField >= 500 {
		FromGin(c).Error(contextMsg,
			zap.Error(err),
			zap.Int("status_code", rfcErr.CodeField),
			zap.String("fosite_error", rfcErr.ErrorField),
			zap.String("fosite_description", rfcErr.DescriptionField),
			zap.String("fosite_hint", rfcErr.HintField),
			zap.String("fosite_debug", rfcErr.DebugField),
		)
		return
	}

	FromGin(c).Warn(contextMsg,
		zap.Error(err),
		zap.Int("status_code", rfcErr.CodeField),
		zap.String("fosite_error", rfcErr.ErrorField),
		zap.String("fosite_description", rfcErr.DescriptionField),
		zap.String("fosite_hint", rfcErr.HintField),
	)
}
