package constants

// Context keys used across the application for Zero Trust context propagation.
const (
	ContextKeyTenantID      = "tenant_id"
	ContextKeyClientIP      = "client_ip"
	ContextKeyUserAgent     = "user_agent"
	ContextKeyTraceID       = "trace_id"
	ContextKeyTokenFamilyID = "token_family_id"
)
