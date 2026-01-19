package allowlist

import "fmt"

// Presets defines built-in rule sets for common use cases.
var Presets = map[string][]Rule{
	"ai-coding-agent": {
		{Host: "api.openai.com"},
		{Host: "api.anthropic.com"},
		{Host: "api.github.com"},
		{Host: "*.githubusercontent.com"},
		{Host: "api.stripe.com", Methods: []string{"GET"}}, // Read-only billing
	},
	"ai-data-agent": {
		{Host: "api.openai.com"},
		{Host: "api.anthropic.com"},
		{Host: "*.snowflakecomputing.com", Methods: []string{"GET", "POST"}},
		{Host: "bigquery.googleapis.com", Methods: []string{"GET", "POST"}},
		{Host: "*.s3.amazonaws.com", Methods: []string{"GET"}}, // Read-only S3
	},
	"strict-openai-only": {
		{Host: "api.openai.com"},
	},
	"strict-anthropic-only": {
		{Host: "api.anthropic.com"},
	},
}

// GetPreset returns a copy of the rules for a named preset.
// The returned slice is safe to modify without affecting the global preset.
func GetPreset(name string) ([]Rule, error) {
	rules, ok := Presets[name]
	if !ok {
		available := make([]string, 0, len(Presets))
		for k := range Presets {
			available = append(available, k)
		}
		return nil, fmt.Errorf("unknown preset %q (available: %v)", name, available)
	}

	// Return a deep copy to prevent mutation of global state
	copy := make([]Rule, len(rules))
	for i, r := range rules {
		copy[i] = Rule{
			Host:    r.Host,
			Methods: append([]string(nil), r.Methods...),
			Paths:   append([]string(nil), r.Paths...),
		}
	}
	return copy, nil
}
