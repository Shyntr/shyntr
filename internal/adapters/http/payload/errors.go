package payload

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Shyntr/shyntr/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type FieldError struct {
	Field   string `json:"field" example:"id"`
	Message string `json:"message" example:"Must be a valid UUID."`
}

type ManagementError struct {
	Type        string       `json:"type" example:"https://shyntr.com/docs/errors/validation_failed"`
	Title       string       `json:"title" example:"Bad Request"`
	Status      int          `json:"status" example:"400"`
	Detail      string       `json:"detail,omitempty" example:"The provided request payload is invalid."`
	Instance    string       `json:"instance,omitempty" example:"/admin/management/tenants"`
	TraceID     string       `json:"trace_id,omitempty" example:"5b8aa5a2-388c-4817-a068-d0658eb11175"`
	Code        string       `json:"code,omitempty" example:"validation_failed"`
	Hint        string       `json:"hint,omitempty" example:"Check the highlighted fields and send the request again."`
	FieldErrors []FieldError `json:"field_errors,omitempty"`
}

type AppError struct {
	StatusCode  int          `json:"status_code" example:"400"`
	UserMessage string       `json:"user_message" example:"Invalid input provided"`
	Code        string       `json:"code,omitempty" example:"validation_failed"`
	Hint        string       `json:"hint,omitempty" example:"Check the highlighted fields and send the request again."`
	FieldErrors []FieldError `json:"field_errors,omitempty"`
	Err         error        `json:"-" swaggerignore:"true"`
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

func NewDetailedAppError(statusCode int, code, userMessage, hint string, fieldErrors []FieldError, err error) *AppError {
	return &AppError{
		StatusCode:  statusCode,
		UserMessage: userMessage,
		Code:        code,
		Hint:        hint,
		FieldErrors: fieldErrors,
		Err:         err,
	}
}

func NewRequiredQueryParamError(param string) *AppError {
	return NewDetailedAppError(
		http.StatusBadRequest,
		"missing_required_parameter",
		fmt.Sprintf("The '%s' query parameter is required.", param),
		fmt.Sprintf("Add the '%s' query parameter and send the request again.", param),
		[]FieldError{{Field: param, Message: "This query parameter is required."}},
		nil,
	)
}

func NewValidationAppError(err error) *AppError {
	fieldErrors := extractFieldErrors(err)
	if len(fieldErrors) == 0 {
		fieldErrors = []FieldError{{Field: "request", Message: "The request body contains invalid or missing values."}}
	}

	return NewDetailedAppError(
		http.StatusBadRequest,
		"validation_failed",
		"Request validation failed. One or more fields contain invalid values.",
		"Check the highlighted fields and send the request again.",
		fieldErrors,
		err,
	)
}

func NewNotFoundAppError(resource string, err error) *AppError {
	return NewDetailedAppError(
		http.StatusNotFound,
		"resource_not_found",
		fmt.Sprintf("%s was not found.", resource),
		fmt.Sprintf("Verify the %s identifier and try again.", strings.ToLower(resource)),
		nil,
		err,
	)
}

func NewConflictAppError(resource, message string, err error) *AppError {
	if message == "" {
		message = fmt.Sprintf("%s already exists.", resource)
	}
	return NewDetailedAppError(
		http.StatusConflict,
		"resource_conflict",
		message,
		fmt.Sprintf("Use a unique value for the %s and send the request again.", strings.ToLower(resource)),
		nil,
		err,
	)
}

func NewOperationAppError(statusCode int, resource, action string, err error) *AppError {
	message, hint, fieldErrors, code := classifyOperationError(statusCode, resource, action, err)
	return NewDetailedAppError(statusCode, code, message, hint, fieldErrors, err)
}

func AbortWithAppError(c *gin.Context, appErr *AppError) {
	writeManagementError(c, appErr)
}

func HandleManagementError(c *gin.Context, statusCode int, userMessage string, err error) {
	writeManagementError(c, NewAppError(statusCode, userMessage, err))
}

func HandleAppError(c *gin.Context, appErr *AppError) {
	writeManagementError(c, appErr)
}

func writeManagementError(c *gin.Context, appErr *AppError) {
	log := logger.FromGin(c)

	var traceID string
	span := trace.SpanFromContext(c.Request.Context())
	if span.SpanContext().HasTraceID() {
		traceID = span.SpanContext().TraceID().String()
	}

	if traceID == "" {
		if requestTraceID, ok := c.Get("trace_id"); ok {
			if value, ok := requestTraceID.(string); ok {
				traceID = value
			}
		}
	}

	logFields := []zap.Field{
		zap.Int("status", appErr.StatusCode),
		zap.String("user_message", appErr.UserMessage),
		zap.String("code", appErr.Code),
	}
	if appErr.Hint != "" {
		logFields = append(logFields, zap.String("hint", appErr.Hint))
	}
	if len(appErr.FieldErrors) > 0 {
		logFields = append(logFields, zap.Any("field_errors", appErr.FieldErrors))
	}
	if appErr.Err != nil {
		logFields = append(logFields, zap.Error(appErr.Err))
	}

	userMessage := appErr.UserMessage
	hint := appErr.Hint
	code := appErr.Code
	fieldErrors := appErr.FieldErrors

	if appErr.StatusCode >= 500 {
		log.Error("Server Error", logFields...)
		userMessage = "The request could not be completed because an internal server error occurred."
		if hint == "" {
			hint = "Try again later. If the problem continues, contact support with the trace_id."
		}
		if code == "" {
			code = "internal_error"
		}
	} else {
		log.Warn("Client Error", logFields...)
		if code == "" {
			code = "request_error"
		}
	}

	problem := ManagementError{
		Type:        fmt.Sprintf("https://shyntr.com/docs/errors/%s", code),
		Title:       http.StatusText(appErr.StatusCode),
		Status:      appErr.StatusCode,
		Detail:      userMessage,
		Instance:    c.Request.URL.Path,
		TraceID:     traceID,
		Code:        code,
		Hint:        hint,
		FieldErrors: fieldErrors,
	}

	c.Header("Content-Type", "application/problem+json")
	c.AbortWithStatusJSON(appErr.StatusCode, problem)
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

func extractFieldErrors(err error) []FieldError {
	if err == nil {
		return nil
	}

	var validationErrs validator.ValidationErrors
	if errors.As(err, &validationErrs) {
		fieldErrors := make([]FieldError, 0, len(validationErrs))
		for _, validationErr := range validationErrs {
			fieldErrors = append(fieldErrors, FieldError{
				Field:   jsonFieldName(validationErr.Field()),
				Message: validationMessage(validationErr),
			})
		}
		return fieldErrors
	}

	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return []FieldError{{Field: "request", Message: "The JSON body is not valid JSON syntax."}}
	}

	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		field := typeErr.Field
		if field == "" {
			field = "request"
		}
		return []FieldError{{Field: jsonFieldName(field), Message: fmt.Sprintf("Expected a value compatible with '%s'.", typeErr.Type.String())}}
	}

	return nil
}

func validationMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return "This field is required."
	case "url":
		return "Must be a valid URL."
	case "uuid", "uuid4":
		return "Must be a valid UUID."
	case "oneof":
		return fmt.Sprintf("Must be one of: %s.", err.Param())
	case "min":
		return fmt.Sprintf("Must contain at least %s item(s) or characters.", err.Param())
	case "max":
		return fmt.Sprintf("Must contain at most %s item(s) or characters.", err.Param())
	case "gte":
		return fmt.Sprintf("Must be greater than or equal to %s.", err.Param())
	case "lte":
		return fmt.Sprintf("Must be less than or equal to %s.", err.Param())
	default:
		return "Contains an invalid value."
	}
}

func jsonFieldName(field string) string {
	if field == "" {
		return "request"
	}
	var builder strings.Builder
	for i, r := range field {
		if i > 0 && r >= 'A' && r <= 'Z' {
			builder.WriteByte('_')
		}
		builder.WriteRune(r)
	}
	return strings.ToLower(builder.String())
}

func pastAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "create":
		return "created"
	case "update":
		return "updated"
	case "delete":
		return "deleted"
	case "list":
		return "listed"
	case "load":
		return "loaded"
	case "fetch":
		return "fetched"
	case "complete":
		return "completed"
	case "save":
		return "saved"
	case "generate":
		return "generated"
	case "initialize":
		return "initialized"
	default:
		if action == "" {
			return "processed"
		}
		return action + "d"
	}
}

func classifyOperationError(statusCode int, resource, action string, err error) (message, hint string, fieldErrors []FieldError, code string) {
	resourceLabel := strings.TrimSpace(resource)
	if resourceLabel == "" {
		resourceLabel = "Resource"
	}

	lowerResource := strings.ToLower(resourceLabel)
	actionLabel := strings.TrimSpace(action)
	if actionLabel == "" {
		actionLabel = "process"
	}

	errText := strings.ToLower(strings.TrimSpace(errorText(err)))

	switch {
	case strings.Contains(errText, "invalid input syntax for type uuid"),
		strings.Contains(errText, "must be a valid uuid"),
		strings.Contains(errText, "invalid uuid"):
		return fmt.Sprintf("%s could not be %s because one of the identifiers is not a valid UUID.", resourceLabel, pastAction(actionLabel)),
			"Provide UUID values in canonical format, for example '550e8400-e29b-41d4-a716-446655440000'.",
			[]FieldError{{Field: "id", Message: "Must be a valid UUID."}},
			"invalid_identifier"
	case strings.Contains(errText, "record not found"),
		strings.Contains(errText, "not found"):
		return fmt.Sprintf("%s was not found.", resourceLabel),
			fmt.Sprintf("Verify the %s identifier and try again.", lowerResource),
			nil,
			"resource_not_found"
	case strings.Contains(errText, "duplicate key"),
		strings.Contains(errText, "already exists"),
		strings.Contains(errText, "unique constraint"):
		return fmt.Sprintf("%s could not be %s because a record with the same unique value already exists.", resourceLabel, pastAction(actionLabel)),
			fmt.Sprintf("Use a unique value for the %s and send the request again.", lowerResource),
			nil,
			"resource_conflict"
	case strings.Contains(errText, "foreign key"),
		strings.Contains(errText, "tenant not found"):
		return fmt.Sprintf("%s could not be %s because a referenced resource was not found.", resourceLabel, pastAction(actionLabel)),
			"Verify all referenced identifiers, especially tenant and connection identifiers, and try again.",
			nil,
			"referenced_resource_not_found"
	case strings.Contains(errText, "metadata url"):
		return fmt.Sprintf("%s could not be %s because the metadata URL is invalid or could not be processed.", resourceLabel, pastAction(actionLabel)),
			"Provide a reachable metadata URL that returns a valid metadata document.",
			[]FieldError{{Field: "metadata_url", Message: "Must be a valid and reachable metadata URL."}},
			"invalid_metadata_url"
	case strings.Contains(errText, "metadata"),
		strings.Contains(errText, "xml"):
		return fmt.Sprintf("%s could not be %s because the metadata document is missing or invalid.", resourceLabel, pastAction(actionLabel)),
			"Provide valid metadata XML or a valid metadata URL and send the request again.",
			[]FieldError{{Field: "idp_metadata_xml", Message: "Provide valid metadata XML or a valid metadata URL."}},
			"invalid_metadata"
	case strings.Contains(errText, "outbound policy"),
		strings.Contains(errText, "restricted or private ip address"),
		strings.Contains(errText, "must use the 'https' scheme"),
		strings.Contains(errText, "violates outbound policy"):
		return fmt.Sprintf("%s could not be %s because the destination is blocked by the outbound security policy.", resourceLabel, pastAction(actionLabel)),
			"Update the outbound policy or use an allowed HTTPS endpoint.",
			nil,
			"outbound_policy_violation"
	case statusCode >= 500:
		return fmt.Sprintf("%s could not be %s because an internal server error occurred.", resourceLabel, pastAction(actionLabel)),
			"Try again later. If the problem continues, contact support with the trace_id.",
			nil,
			"internal_error"
	default:
		return fmt.Sprintf("%s could not be %s.", resourceLabel, pastAction(actionLabel)),
			fmt.Sprintf("Review the provided %s configuration and try again.", lowerResource),
			nil,
			"operation_failed"
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type ProtocolError struct {
	Error            string `json:"error" example:"invalid_request"`
	ErrorDescription string `json:"error_description,omitempty" example:"The request is missing a required parameter."`
}

func writeProtocolError(c *gin.Context, statusCode int, code, description string, err error, abort bool) {
	LogOnlyError(c, statusCode, description, err)
	body := ProtocolError{Error: code, ErrorDescription: description}
	if abort {
		c.AbortWithStatusJSON(statusCode, body)
		return
	}
	c.JSON(statusCode, body)
}

func WriteOAuth2Error(c *gin.Context, statusCode int, code, description string, err error) {
	writeProtocolError(c, statusCode, code, description, err, false)
}

func AbortWithOAuth2Error(c *gin.Context, statusCode int, code, description string, err error) {
	writeProtocolError(c, statusCode, code, description, err, true)
}

func WriteOIDCError(c *gin.Context, statusCode int, code, description string, err error) {
	writeProtocolError(c, statusCode, code, description, err, false)
}

func AbortWithOIDCError(c *gin.Context, statusCode int, code, description string, err error) {
	writeProtocolError(c, statusCode, code, description, err, true)
}

func WriteSAMLError(c *gin.Context, statusCode int, code, description string, err error) {
	writeProtocolError(c, statusCode, code, description, err, false)
}

func AbortWithSAMLError(c *gin.Context, statusCode int, code, description string, err error) {
	writeProtocolError(c, statusCode, code, description, err, true)
}
