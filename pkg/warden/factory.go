package warden

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
)

// ValidBackends is the set of supported sandbox backend names.
var ValidBackends = map[string]bool{
	"auto":       true,
	"seatbelt":   true,
	"bubblewrap": true,
	"srt":        true,
	"anthropic":  true,
}

// validBackendNames returns a sorted, comma-separated list of valid backend names.
func validBackendNames() string {
	names := make([]string, 0, len(ValidBackends))
	for k := range ValidBackends {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// NewBackend creates a sandbox backend by name.
// Valid values: "auto", "seatbelt", "bubblewrap", "srt", "anthropic"
func NewBackend(backendType string) (Backend, error) {
	if !ValidBackends[backendType] {
		return nil, fmt.Errorf("unknown sandbox backend: %s (available: %s)",
			backendType, validBackendNames())
	}

	switch backendType {
	case "auto":
		return newAutoBackend()
	case "seatbelt":
		return newSeatbeltBackend()
	case "bubblewrap":
		return newBubblewrapBackend()
	case "srt", "anthropic":
		return newSrtBackend()
	default:
		// This should never happen due to ValidBackends check above
		return nil, fmt.Errorf("unknown sandbox backend: %s", backendType)
	}
}

func newAutoBackend() (Backend, error) {
	switch runtime.GOOS {
	case "darwin":
		return newSeatbeltBackend()
	case "linux":
		return newBubblewrapBackend()
	default:
		return nil, fmt.Errorf("sandbox not supported on %s", runtime.GOOS)
	}
}

func newSeatbeltBackend() (Backend, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("seatbelt only available on macOS")
	}
	return &SeatbeltBackend{}, nil
}

func newBubblewrapBackend() (Backend, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("bubblewrap only available on Linux")
	}
	// TODO: Implement bubblewrap backend
	return nil, fmt.Errorf("bubblewrap backend not yet implemented")
}

func newSrtBackend() (Backend, error) {
	return NewSrtBackend()
}
