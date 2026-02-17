package mapper

import (
	"strings"
)

type Mapper struct{}

func New() *Mapper {
	return &Mapper{}
}

func (m *Mapper) Map(input map[string]interface{}, mapping map[string]string) (map[string]interface{}, error) {
	if len(mapping) == 0 {
		return make(map[string]interface{}), nil
	}

	output := make(map[string]interface{})
	for targetField, sourceField := range mapping {
		val, ok := m.getValue(input, sourceField)
		if ok {
			output[targetField] = val
		}
	}
	return output, nil
}

func (m *Mapper) getValue(data map[string]interface{}, path string) (interface{}, bool) {
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
