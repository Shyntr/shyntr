package mapper_test

import (
	"testing"

	"github.com/Shyntr/shyntr/internal/application/mapper"
	"github.com/Shyntr/shyntr/internal/domain/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMapper() *mapper.Mapper {
	return mapper.New()
}

// ---------------------------------------------------------------------------
// Map() tests
// ---------------------------------------------------------------------------

func TestMapper_Map_EmptyMapping(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"sub": "alice"}
	out, err := m.Map(input, nil)
	require.NoError(t, err)
	assert.Empty(t, out, "empty mapping must return empty output")
}

func TestMapper_Map_SimpleKeyPassthrough(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"email": "alice@example.com"}
	mapping := map[string]model.AttributeMappingRule{
		"email": {Source: "email", Type: "string"},
	}
	out, err := m.Map(input, mapping)
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", out["email"])
}

func TestMapper_Map_ConstantValueInjection(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{}
	mapping := map[string]model.AttributeMappingRule{
		"source": {Value: "ldap", Type: "string"},
	}
	out, err := m.Map(input, mapping)
	require.NoError(t, err)
	assert.Equal(t, "ldap", out["source"])
}

func TestMapper_Map_MissingSourceKey_Skipped(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"email": "alice@example.com"}
	mapping := map[string]model.AttributeMappingRule{
		"phone": {Source: "phone_number", Type: "string"},
	}
	out, err := m.Map(input, mapping)
	require.NoError(t, err)
	_, ok := out["phone"]
	assert.False(t, ok, "missing source key must be skipped in output")
}

func TestMapper_Map_FallbackUsedWhenSourceMissing(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"preferred_name": "Alice"}
	mapping := map[string]model.AttributeMappingRule{
		"name": {Source: "display_name", Fallback: "preferred_name", Type: "string"},
	}
	out, err := m.Map(input, mapping)
	require.NoError(t, err)
	assert.Equal(t, "Alice", out["name"])
}

func TestMapper_Map_MultiValueAttribute(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{
		"groups": []string{"admin", "dev"},
	}
	mapping := map[string]model.AttributeMappingRule{
		"roles": {Source: "groups", Type: "string_array"},
	}
	out, err := m.Map(input, mapping)
	require.NoError(t, err)
	roles, ok := out["roles"].([]string)
	require.True(t, ok)
	assert.Contains(t, roles, "admin")
	assert.Contains(t, roles, "dev")
}

func TestMapper_Map_NestedKey(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{
		"profile": map[string]interface{}{
			"email": "nested@example.com",
		},
	}
	mapping := map[string]model.AttributeMappingRule{
		"email": {Source: "profile.email", Type: "string"},
	}
	out, err := m.Map(input, mapping)
	require.NoError(t, err)
	assert.Equal(t, "nested@example.com", out["email"])
}

// ---------------------------------------------------------------------------
// castValue() tests — accessed via Map() with known type specifiers
// ---------------------------------------------------------------------------

func TestMapper_CastValue_String(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"val": "hello"}
	mapping := map[string]model.AttributeMappingRule{"out": {Source: "val", Type: "string"}}
	out, err := m.Map(input, mapping)
	require.NoError(t, err)
	assert.Equal(t, "hello", out["out"])
}

func TestMapper_CastValue_Integer(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"val": "42"}
	mapping := map[string]model.AttributeMappingRule{"out": {Source: "val", Type: "integer"}}
	out, err := m.Map(input, mapping)
	require.NoError(t, err)
	assert.Equal(t, 42, out["out"])
}

func TestMapper_CastValue_Boolean_True(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"val": "true"}
	mapping := map[string]model.AttributeMappingRule{"out": {Source: "val", Type: "boolean"}}
	out, err := m.Map(input, mapping)
	require.NoError(t, err)
	assert.Equal(t, true, out["out"])
}

func TestMapper_CastValue_Boolean_False(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"val": "false"}
	mapping := map[string]model.AttributeMappingRule{"out": {Source: "val", Type: "boolean"}}
	out, err := m.Map(input, mapping)
	require.NoError(t, err)
	assert.Equal(t, false, out["out"])
}

func TestMapper_CastValue_StringArray_FromSlice(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"val": []string{"a", "b"}}
	mapping := map[string]model.AttributeMappingRule{"out": {Source: "val", Type: "string_array"}}
	out, err := m.Map(input, mapping)
	require.NoError(t, err)
	arr, ok := out["out"].([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"a", "b"}, arr)
}

func TestMapper_CastValue_StringArray_FromInterfaceSlice(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"val": []interface{}{"x", "y"}}
	mapping := map[string]model.AttributeMappingRule{"out": {Source: "val", Type: "string_array"}}
	out, err := m.Map(input, mapping)
	require.NoError(t, err)
	arr, ok := out["out"].([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"x", "y"}, arr)
}

func TestMapper_CastValue_StringArray_FromCSV(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"val": "a,b,c"}
	mapping := map[string]model.AttributeMappingRule{"out": {Source: "val", Type: "string_array"}}
	out, err := m.Map(input, mapping)
	require.NoError(t, err)
	arr, ok := out["out"].([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"a", "b", "c"}, arr)
}

func TestMapper_CastValue_StringFromSliceTakesFirst(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"val": []string{"first", "second"}}
	mapping := map[string]model.AttributeMappingRule{"out": {Source: "val", Type: "string"}}
	out, err := m.Map(input, mapping)
	require.NoError(t, err)
	assert.Equal(t, "first", out["out"])
}

func TestMapper_CastValue_UnknownType_DefaultsToString(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"val": 123}
	mapping := map[string]model.AttributeMappingRule{"out": {Source: "val", Type: "nonexistent_type"}}
	out, err := m.Map(input, mapping)
	require.NoError(t, err)
	assert.Equal(t, "123", out["out"])
}
