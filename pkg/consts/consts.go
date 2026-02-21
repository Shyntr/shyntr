package consts

const (
	// Session Cookie Name
	SessionCookieName = "shyntr_session"

	// Key IDs
	SigningKeyID = "shyntr-key-1"

	// Context Keys
	ContextKeyRequestID = "RequestID"
	ContextKeyTraceID   = "TraceID"
	ContextKeySpanID    = "SpanID"

	// Headers
	HeaderTraceParent = "traceparent"
	HeaderTraceState  = "tracestate"

	// Environment Variables
	EnvAppSecret     = "APP_SECRET"
	EnvDatabaseDSN   = "DSN"
	EnvRSAPrivateKey = "APP_PRIVATE_KEY_BASE64"
)
