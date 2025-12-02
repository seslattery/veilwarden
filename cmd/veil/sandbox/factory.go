package sandbox

import (
	"fmt"
)

// NewBackend creates a sandbox backend by name.
func NewBackend(backendType string) (Backend, error) {
	switch backendType {
	case "anthropic":
		// Will be implemented in Task 3
		return nil, fmt.Errorf("anthropic backend not yet implemented")
	default:
		return nil, fmt.Errorf("unknown sandbox backend: %s (available: anthropic)", backendType)
	}
}
