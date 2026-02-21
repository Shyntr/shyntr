package models

type AttributeMappingRule struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	Fallback string `json:"fallback,omitempty"`
	Value    string `json:"value,omitempty"`
}
