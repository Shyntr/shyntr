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

// ---------------------------------------------------------------------------
// MapWithPassthrough() tests (attribute-release: passthrough + exclude)
// ---------------------------------------------------------------------------

// (a) passthrough FALSE, mapping {t<-s}: only t present, s absent (whitelist).
func TestMapWithPassthrough_WhitelistMode(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"groups": []interface{}{"admin"}, "email": "a@x.io"}
	mapping := map[string]model.AttributeMappingRule{
		"roles": {Source: "groups", Target: "roles", Type: "string_array"},
	}
	out, err := m.MapWithPassthrough(input, mapping, false, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"admin"}, out["roles"], "target must be present")
	assert.NotContains(t, out, "groups", "source must be absent in whitelist mode")
	assert.NotContains(t, out, "email", "unmapped claim must be absent in whitelist mode")
}

// (b) passthrough TRUE, mapping {t<-s}: t present AND s ABSENT (move), other
// unmapped claims still present.
func TestMapWithPassthrough_MoveRemovesSource(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"groups": []interface{}{"admin"}, "email": "a@x.io"}
	mapping := map[string]model.AttributeMappingRule{
		"roles": {Source: "groups", Target: "roles", Type: "string_array"},
	}
	out, err := m.MapWithPassthrough(input, mapping, true, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"admin"}, out["roles"], "target must be present")
	assert.NotContains(t, out, "groups", "source must be REMOVED (move) in passthrough mode")
	assert.Equal(t, "a@x.io", out["email"], "unmapped claim must survive passthrough")
}

// (c) passthrough TRUE, source==target rule: the claim stays (transform in place).
func TestMapWithPassthrough_SourceEqualsTargetKept(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"email": "a@x.io", "name": "Alice"}
	mapping := map[string]model.AttributeMappingRule{
		"email": {Source: "email", Target: "email", Type: "string"},
	}
	out, err := m.MapWithPassthrough(input, mapping, true, nil)
	require.NoError(t, err)
	assert.Equal(t, "a@x.io", out["email"], "source==target transform must keep the claim")
	assert.Equal(t, "Alice", out["name"], "unmapped claim must survive")
}

// (c2) passthrough TRUE: a source that is itself another rule's target is NOT removed.
func TestMapWithPassthrough_SourceIsAnotherRulesTargetKept(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"a": "1", "b": "2"}
	mapping := map[string]model.AttributeMappingRule{
		"x": {Source: "b", Target: "x", Type: "string"}, // moves b -> x
		"b": {Source: "a", Target: "b", Type: "string"}, // b is also a target
	}
	out, err := m.MapWithPassthrough(input, mapping, true, nil)
	require.NoError(t, err)
	assert.Equal(t, "2", out["x"], "b moved to x")
	assert.Equal(t, "1", out["b"], "b is another rule's target and must survive as that target")
	assert.NotContains(t, out, "a", "a moved to b, source a removed")
}

// (d) exclude ["x"]: x absent in both passthrough modes.
func TestMapWithPassthrough_ExcludeBothModes(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"email": "a@x.io", "ssn": "123"}
	mapping := map[string]model.AttributeMappingRule{
		"email_addr": {Source: "email", Target: "email_addr", Type: "string"},
	}

	// passthrough true: exclude removes ssn even though it would pass through.
	outTrue, err := m.MapWithPassthrough(input, mapping, true, []string{"ssn"})
	require.NoError(t, err)
	assert.NotContains(t, outTrue, "ssn", "exclude must remove claim in passthrough mode")
	assert.Equal(t, "a@x.io", outTrue["email_addr"])

	// passthrough false: exclude removes a mapped target when listed.
	outFalse, err := m.MapWithPassthrough(input, map[string]model.AttributeMappingRule{
		"ssn": {Source: "ssn", Target: "ssn", Type: "string"},
	}, false, []string{"ssn"})
	require.NoError(t, err)
	assert.NotContains(t, outFalse, "ssn", "exclude must remove a mapped target in whitelist mode")
}

// (f) empty mapping + passthrough FALSE: unchanged from Map() today (regression guard).
func TestMapWithPassthrough_EmptyMappingFalse_RegressionGuard(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"email": "a@x.io", "name": "Alice"}

	out, err := m.MapWithPassthrough(input, nil, false, nil)
	require.NoError(t, err)

	direct, err := m.Map(input, nil)
	require.NoError(t, err)
	assert.Equal(t, direct, out, "empty mapping + passthrough=false must equal Map() output (empty whitelist)")
	assert.Empty(t, out)
}

// empty mapping + passthrough TRUE: input returned unchanged minus excludes.
func TestMapWithPassthrough_EmptyMappingTrue_ReturnsInputMinusExcludes(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"email": "a@x.io", "name": "Alice", "ssn": "123"}
	out, err := m.MapWithPassthrough(input, nil, true, []string{"ssn"})
	require.NoError(t, err)
	assert.Equal(t, "a@x.io", out["email"])
	assert.Equal(t, "Alice", out["name"])
	assert.NotContains(t, out, "ssn")
}

// The input map must never be mutated.
func TestMapWithPassthrough_DoesNotMutateInput(t *testing.T) {
	m := newMapper()
	input := map[string]interface{}{"groups": "admin", "ssn": "123"}
	mapping := map[string]model.AttributeMappingRule{
		"roles": {Source: "groups", Target: "roles", Type: "string"},
	}
	_, err := m.MapWithPassthrough(input, mapping, true, []string{"ssn"})
	require.NoError(t, err)
	assert.Contains(t, input, "groups", "input must not be mutated by the move")
	assert.Contains(t, input, "ssn", "input must not be mutated by exclude")
}
