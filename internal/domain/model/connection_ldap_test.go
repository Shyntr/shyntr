package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLDAPConnection_JSONOmitsBindPassword(t *testing.T) {
	conn := LDAPConnection{
		ID:           "ldap-1",
		TenantID:     "tenant-a",
		Name:         "Corp LDAP",
		ServerURL:    "ldaps://ldap.example.com:636",
		BindDN:       "cn=svc,dc=example,dc=com",
		BindPassword: "super-secret",
		BaseDN:       "dc=example,dc=com",
		Active:       true,
		CreatedAt:    time.Unix(1700000000, 0).UTC(),
	}

	data, err := json.Marshal(conn)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	output := string(data)
	if strings.Contains(output, "super-secret") {
		t.Fatalf("serialized LDAPConnection must not contain bind password: %s", output)
	}
	if strings.Contains(output, "BindPassword") {
		t.Fatalf("serialized LDAPConnection must not contain BindPassword field name: %s", output)
	}
}
