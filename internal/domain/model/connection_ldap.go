package model

import (
	"errors"
	"time"
)

// LDAPConnection represents an LDAP/Active-Directory identity provider connection.
// BindPassword is never serialized to JSON and never reaches audit log details.
type LDAPConnection struct {
	ID                    string                          `json:"id"`
	TenantID              string                          `json:"tenant_id"`
	Name                  string                          `json:"name"`
	ServerURL             string                          `json:"server_url"`
	BindDN                string                          `json:"bind_dn"`
	BindPassword          string                          `json:"-"` // never serialized, never logged
	BaseDN                string                          `json:"base_dn"`
	UserSearchFilter      string                          `json:"user_search_filter"`
	UserSearchAttributes  []string                        `json:"user_search_attributes"`
	GroupSearchFilter     string                          `json:"group_search_filter"`
	GroupSearchBaseDN     string                          `json:"group_search_base_dn"`
	AttributeMapping      map[string]AttributeMappingRule `json:"attribute_mapping"`
	StartTLS              bool                            `json:"start_tls"`
	TLSInsecureSkipVerify bool                            `json:"tls_insecure_skip_verify"`
	Active                bool                            `json:"active"`
	CreatedAt             time.Time                       `json:"created_at"`
	UpdatedAt             time.Time                       `json:"updated_at,omitempty"`
}

// LDAPEntry is a single directory entry returned by an LDAP search.
type LDAPEntry struct {
	DN         string              `json:"dn"`
	Attributes map[string][]string `json:"attributes"`
}

func (c *LDAPConnection) Validate() error {
	if c.TenantID == "" {
		return errors.New("tenant_id is required")
	}
	if c.ServerURL == "" {
		return errors.New("server_url is required")
	}
	if c.BaseDN == "" {
		return errors.New("base_dn is required")
	}
	return nil
}
