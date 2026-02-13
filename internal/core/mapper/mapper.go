package mapper

import (
	"encoding/json"
	"fmt"
)

type Mapper struct{}

func New() *Mapper {
	return &Mapper{}
}

// Map transforms source attributes based on the mapping rules.
// mappingJSON format: {"target_key": "source_key"}
// Example: {"email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"}
//
// Rules:
// 1. If mappingJSON is empty, returns the source as-is (Pass-through mode).
// 2. If mappingJSON exists, ONLY the defined keys are transferred (Whitelist mode).
func (m *Mapper) Map(source map[string]interface{}, mappingJSON []byte) (map[string]interface{}, error) {
	if len(mappingJSON) == 0 || string(mappingJSON) == "{}" || string(mappingJSON) == "null" {
		return source, nil
	}

	var rules map[string]string
	if err := json.Unmarshal(mappingJSON, &rules); err != nil {
		return nil, fmt.Errorf("invalid mapping json: %w", err)
	}

	target := make(map[string]interface{})
	for targetKey, sourceKey := range rules {
		if val, ok := source[sourceKey]; ok {
			target[targetKey] = val
		}
	}

	return target, nil
}
