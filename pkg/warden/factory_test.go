package warden

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBackend_Auto(t *testing.T) {
	backend, err := NewBackend("auto")
	require.NoError(t, err)
	require.NotNil(t, backend)

	// Type depends on OS
	switch runtime.GOOS {
	case "darwin":
		_, ok := backend.(*SeatbeltBackend)
		assert.True(t, ok, "expected SeatbeltBackend on darwin")
	case "linux":
		// Will be BubblewrapBackend when implemented
		t.Skip("bubblewrap not yet implemented")
	default:
		t.Errorf("unexpected OS: %s", runtime.GOOS)
	}
}

func TestNewBackend_Seatbelt(t *testing.T) {
	if runtime.GOOS != "darwin" {
		_, err := NewBackend("seatbelt")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only available on macOS")
		return
	}

	backend, err := NewBackend("seatbelt")
	require.NoError(t, err)
	_, ok := backend.(*SeatbeltBackend)
	assert.True(t, ok)
}

func TestNewBackend_Unknown(t *testing.T) {
	_, err := NewBackend("unknown")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}
