package port

type AuditLogger interface {
	Log(tenantID string, actor string, action string, ip string, ua string, details map[string]interface{})
}
