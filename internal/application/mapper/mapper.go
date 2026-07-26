package mapper

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Shyntr/shyntr/internal/domain/model"
)

type Mapper struct{}

func New() *Mapper {
	return &Mapper{}
}

func (m *Mapper) Map(input map[string]interface{}, mapping map[string]model.AttributeMappingRule) (map[string]interface{}, error) {
	if len(mapping) == 0 {
		return make(map[string]interface{}), nil
	}

	output := make(map[string]interface{})
	for targetField, rule := range mapping {
		var rawValue interface{}
		var found bool

		if rule.Value != "" {
			rawValue = rule.Value
			found = true
		} else {
			rawValue, found = m.getValue(input, rule.Source)

			if (!found || rawValue == nil || rawValue == "") && rule.Fallback != "" {
				rawValue, found = m.getValue(input, rule.Fallback)
			}
		}

		if found && rawValue != nil {
			output[targetField] = m.castValue(rawValue, rule.Type)
		}
	}
	return output, nil
}

// MapWithPassthrough applies an attribute-mapping policy: the rename/cast rules of
// Map, plus a passthrough mode and an exclude denylist.
//
//   - passthrough == false: only the mapped targets are returned (the current
//     whitelist behaviour). An empty mapping therefore yields an empty result,
//     identical to Map today.
//   - passthrough == true: every input claim is returned, MINUS each rule's source
//     (a mapping is a MOVE), PLUS the mapped targets. A rule whose source is empty
//     (a constant Value rule), whose source equals its own target (a transform in
//     place, not a move), or whose source is itself another rule's target is NOT
//     removed. An empty mapping therefore yields the input unchanged (minus excludes).
//   - exclude: every listed claim name is removed from the result in BOTH modes.
//
// The returned map is always a fresh copy; the input is never mutated.
func (m *Mapper) MapWithPassthrough(input map[string]interface{},
	mapping map[string]model.AttributeMappingRule, passthrough bool, exclude []string) (map[string]interface{}, error) {

	mapped, err := m.Map(input, mapping)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if passthrough {
		result = make(map[string]interface{}, len(input)+len(mapped))
		for k, v := range input {
			result[k] = v
		}
		// A source that is itself another rule's target must survive the move.
		targets := make(map[string]bool, len(mapping))
		for targetField := range mapping {
			targets[targetField] = true
		}
		for targetField, rule := range mapping {
			if rule.Source != "" && rule.Source != targetField && !targets[rule.Source] {
				delete(result, rule.Source)
			}
		}
		for k, v := range mapped {
			result[k] = v
		}
	} else {
		result = mapped
	}

	for _, name := range exclude {
		delete(result, name)
	}

	return result, nil
}

func (m *Mapper) getValue(data map[string]interface{}, path string) (interface{}, bool) {
	if path == "" {
		return nil, false
	}
	keys := strings.Split(path, ".")
	var current interface{} = data

	for _, key := range keys {
		if asMap, ok := current.(map[string]interface{}); ok {
			val, exists := asMap[key]
			if !exists {
				return nil, false
			}
			current = val
		} else {
			return nil, false
		}
	}
	return current, true
}

func (m *Mapper) castValue(val interface{}, targetType string) interface{} {
	strVal := fmt.Sprintf("%v", val)

	switch targetType {
	case "boolean":
		b, _ := strconv.ParseBool(strVal)
		return b
	case "integer":
		i, _ := strconv.Atoi(strVal)
		return i
	case "string_array":
		if slice, ok := val.([]interface{}); ok {
			var res []string
			for _, s := range slice {
				res = append(res, fmt.Sprintf("%v", s))
			}
			return res
		}
		if slice, ok := val.([]string); ok {
			return slice
		}
		if strings.Contains(strVal, ",") {
			parts := strings.Split(strVal, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			return parts
		}
		return []string{strVal}
	case "string":
		fallthrough
	default:
		if slice, ok := val.([]string); ok && len(slice) > 0 {
			return slice[0]
		}
		if slice, ok := val.([]interface{}); ok && len(slice) > 0 {
			return fmt.Sprintf("%v", slice[0])
		}
		return strVal
	}
}
