package sandbox

import (
	"fmt"
)

// NewBackend creates a sandbox backend by name.
func NewBackend(backendType string) (Backend, error) {
	switch backendType {
	case "anthropic":
		return NewAnthropicBackend()
	default:
		return nil, fmt.Errorf("unknown sandbox backend: %s (available: anthropic)", backendType)
	}
}
