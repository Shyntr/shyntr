package logger

import (
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	Log  *zap.Logger
	once sync.Once
)

// InitLogger initializes the global logger.
// In production, it outputs JSON. In dev, it outputs console-friendly text.
func InitLogger() {
	once.Do(func() {
		env := os.Getenv("GO_ENV")

		var config zap.Config
		if env == "production" {
			config = zap.NewProductionConfig()
			config.EncoderConfig.TimeKey = "timestamp"
			config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		} else {
			config = zap.NewDevelopmentConfig()
			config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		}

		var err error
		Log, err = config.Build()
		if err != nil {
			panic("Failed to initialize logger: " + err.Error())
		}
	})
}

// Sync flushes any buffered log entries.
func Sync() {
	if Log != nil {
		_ = Log.Sync() // Ignore error on sync (common in stdout logging)
	}
}
