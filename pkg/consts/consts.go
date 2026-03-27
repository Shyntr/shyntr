package consts

const (
	// Session Cookie Name
	SessionCookieName = "shyntr_session"

	// Key IDs
	SigningKeyID = "shyntr-key-1"

	// Context Keys
	ContextKeyTenantID      = "tenant_id"
	ContextKeyClientIP      = "client_ip"
	ContextKeyUserAgent     = "user_agent"
	ContextKeyTokenFamilyID = "token_family_id"

	// Headers
	HeaderTraceParent = "traceparent"
	HeaderTraceState  = "tracestate"

	// Environment Variables
	EnvAppSecret     = "APP_SECRET"
	EnvDatabaseDSN   = "DSN"
	EnvRSAPrivateKey = "APP_PRIVATE_KEY_BASE64"
)
