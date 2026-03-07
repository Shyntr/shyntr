package utils_test

import (
	"testing"

	"github.com/nevzatcirak/shyntr/internal/application/utils"
	"github.com/stretchr/testify/assert"
)

func TestMapClaims(t *testing.T) {
	subject := "user-123"

	rawContextMap := map[string]interface{}{
		"tenant_id":             "tenant-a",
		"name":                  "John Doe",
		"email":                 "john@example.com",
		"email_verified":        true,
		"phone_number":          "+123456789",
		"secret_internal_score": 99,
		"address":               "123 Main St",
	}

	tests := []struct {
		name           string
		scopes         []string
		expectedKeys   []string
		unexpectedKeys []string
	}{
		{
			name:           "Sadece sub ve tenant_id (En Az Ayrıcalık)",
			scopes:         []string{},
			expectedKeys:   []string{"sub", "tenant_id"},
			unexpectedKeys: []string{"name", "email", "secret_internal_score"},
		},
		{
			name:           "Email Scope talebi",
			scopes:         []string{"email"},
			expectedKeys:   []string{"sub", "tenant_id", "email", "email_verified"},
			unexpectedKeys: []string{"name", "phone_number", "secret_internal_score"},
		},
		{
			name:           "Profile ve Email Scope talebi",
			scopes:         []string{"profile", "email"},
			expectedKeys:   []string{"sub", "tenant_id", "name", "email", "email_verified"},
			unexpectedKeys: []string{"phone_number", "address", "secret_internal_score"},
		},
		{
			name:           "Özel (Custom) Scope talebi",
			scopes:         []string{"custom_scope_not_in_map"},
			expectedKeys:   []string{"sub", "tenant_id"},
			unexpectedKeys: []string{"secret_internal_score"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utils.MapClaims(subject, rawContextMap, tt.scopes)

			for _, key := range tt.expectedKeys {
				_, exists := result[key]
				assert.True(t, exists, "Expected key '%s' missing in mapped claims", key)
			}

			for _, key := range tt.unexpectedKeys {
				_, exists := result[key]
				assert.False(t, exists, "Unexpected key '%s' leaked in mapped claims", key)
			}

			assert.Equal(t, subject, result["sub"])
		})
	}
}
