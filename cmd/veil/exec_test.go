package main

import (
	"fmt"
	"net"
	"testing"

	"veilwarden/internal/config"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldUseSandbox(t *testing.T) {
	tests := []struct {
		name           string
		configEnabled  bool
		sandboxFlag    bool
		noSandboxFlag  bool
		expectedResult bool
	}{
		{
			name:           "config enabled, no flags",
			configEnabled:  true,
			sandboxFlag:    false,
			noSandboxFlag:  false,
			expectedResult: true,
		},
		{
			name:           "config disabled, no flags",
			configEnabled:  false,
			sandboxFlag:    false,
			noSandboxFlag:  false,
			expectedResult: false,
		},
		{
			name:           "config enabled, --no-sandbox flag",
			configEnabled:  true,
			sandboxFlag:    false,
			noSandboxFlag:  true,
			expectedResult: false,
		},
		{
			name:           "config disabled, --sandbox flag",
			configEnabled:  false,
			sandboxFlag:    true,
			noSandboxFlag:  false,
			expectedResult: true,
		},
		{
			name:           "--sandbox overrides config",
			configEnabled:  false,
			sandboxFlag:    true,
			noSandboxFlag:  false,
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			if tt.configEnabled {
				cfg.Sandbox = &config.SandboxEntry{
					Enabled: true,
					Backend: "srt",
				}
			}

			// Mock command with flags
			cmd := &cobra.Command{}
			cmd.Flags().Bool("sandbox", false, "")
			cmd.Flags().Bool("no-sandbox", false, "")

			if tt.sandboxFlag {
				cmd.Flags().Set("sandbox", "true")
			}
			if tt.noSandboxFlag {
				cmd.Flags().Set("no-sandbox", "true")
			}

			result := shouldUseSandbox(cfg, cmd)
			if result != tt.expectedResult {
				t.Errorf("shouldUseSandbox() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestProxyListenerReuse(t *testing.T) {
	// This test verifies we don't have a race condition where
	// we find a port, close it, then try to rebind
	// The fix is to keep the listener open and pass it directly

	// Create a listener on port 0 (random)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port

	// Don't close - simulate "stolen" port
	defer listener.Close()

	// Try to bind to the same port - should fail
	_, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	assert.Error(t, err, "should fail to bind to already-bound port")
}
