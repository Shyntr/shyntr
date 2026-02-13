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
