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
