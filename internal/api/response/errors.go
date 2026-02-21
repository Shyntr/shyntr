package response

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nevzatcirak/shyntr/pkg/logger"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// ManagementError represents the RFC 9457 Problem Details for HTTP APIs
type ManagementError struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
	TraceID  string `json:"trace_id,omitempty"`
}

// HandleManagementError logs the error with OTel Trace ID and returns an RFC 9457 compliant JSON response.
func HandleManagementError(c *gin.Context, statusCode int, userMessage string, err error) {
	log := logger.FromGin(c)

	var traceID string
	span := trace.SpanFromContext(c.Request.Context())
	if span.SpanContext().HasTraceID() {
		traceID = span.SpanContext().TraceID().String()
	}

	logFields := []zap.Field{
		zap.Int("status", statusCode),
		zap.String("user_message", userMessage),
	}
	if err != nil {
		logFields = append(logFields, zap.Error(err))
	}

	if statusCode >= 500 {
		log.Error("Server Error", logFields...)
		userMessage = "An unexpected error occurred on the server. Please contact support with your trace_id."
	} else {
		log.Warn("Client Error", logFields...)
	}

	problem := ManagementError{
		Type:     fmt.Sprintf("https://shyntr.com/docs/errors/%d", statusCode),
		Title:    http.StatusText(statusCode),
		Status:   statusCode,
		Detail:   userMessage,
		Instance: c.Request.URL.Path,
		TraceID:  traceID,
	}

	c.Header("Content-Type", "application/problem+json")
	c.AbortWithStatusJSON(statusCode, problem)
}

func LogOnlyError(c *gin.Context, statusCode int, userMessage string, err error) {
	log := logger.FromGin(c)

	logFields := []zap.Field{
		zap.Int("status", statusCode),
		zap.String("user_message", userMessage),
	}
	if err != nil {
		logFields = append(logFields, zap.Error(err))
	}

	if statusCode >= 500 {
		log.Error("Server Error (Protocol)", logFields...)
	} else {
		log.Warn("Client Error (Protocol)", logFields...)
	}
}

type AppError struct {
	StatusCode  int
	UserMessage string
	Err         error
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.UserMessage
}

func (e *AppError) Unwrap() error {
	return e.Err
}

func NewAppError(statusCode int, userMessage string, err error) *AppError {
	return &AppError{
		StatusCode:  statusCode,
		UserMessage: userMessage,
		Err:         err,
	}
}
