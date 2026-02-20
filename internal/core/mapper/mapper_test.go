package mapper_test

import (
	"testing"

	"github.com/nevzatcirak/shyntr/internal/core/mapper"
	"github.com/stretchr/testify/assert"
)

func TestAttributeMapper_DataSanitization(t *testing.T) {
	attrMapper := mapper.New()

	rawIdpData := map[string]interface{}{
		"sub": "ext-user-123",
		"personal_info": map[string]interface{}{
			"first_name": "John",
			"last_name":  "Doe",
			"contact": map[string]interface{}{
				"primary_email": "john@example.com",
			},
		},
		"age": 30,
	}

	t.Run("Map Flat and Nested Attributes Safely", func(t *testing.T) {
		rules := map[string]string{
			"email":      "personal_info.contact.primary_email",
			"given_name": "personal_info.first_name",
			"subject":    "sub",
		}

		result, err := attrMapper.Map(rawIdpData, rules)
		assert.NoError(t, err)

		assert.Equal(t, "john@example.com", result["email"])
		assert.Equal(t, "John", result["given_name"])
		assert.Equal(t, "ext-user-123", result["subject"])
	})

	t.Run("Handle Missing or Malformed Data Gracefully", func(t *testing.T) {
		rules := map[string]string{
			"email":     "personal_info.contact.secondary_email",
			"last_name": "does_not_exist",
			"bad_path":  "personal_info.first_name.invalid",
		}

		result, err := attrMapper.Map(rawIdpData, rules)
		assert.NoError(t, err)

		assert.Empty(t, result["email"])
		assert.Empty(t, result["last_name"])
		assert.Empty(t, result["bad_path"])
	})
}
