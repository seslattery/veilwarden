package warden

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateProfile(t *testing.T) {
	cfg := &Config{
		Command:           []string{"python", "agent.py"},
		ProxyAddr:         "127.0.0.1:8080",
		AllowedWritePaths: []string{"/tmp/project"},
		DeniedReadPaths:   []string{"~/.ssh", "~/.aws"},
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	// Check basic structure
	assert.Contains(t, profile, "(version 1)")
	assert.Contains(t, profile, "(deny default)")

	// Check proxy port (only localhost, not 127.0.0.1 due to seatbelt limitations)
	assert.Contains(t, profile, "localhost:8080")

	// Check paths are expanded
	assert.Contains(t, profile, "(deny file-read* (subpath")
	assert.Contains(t, profile, "(allow file-write* (subpath")
}

func TestGenerateProfile_WithGlobs(t *testing.T) {
	cfg := &Config{
		Command:           []string{"echo"},
		ProxyAddr:         "127.0.0.1:8080",
		DeniedReadPaths:   []string{"~/.config/*/credentials"},
		AllowedWritePaths: []string{"/tmp/project/agent-*"},
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	// Globs should be converted to regex
	assert.Contains(t, profile, "(regex #\"")
	assert.Contains(t, profile, "[^/]*") // * -> [^/]*
}

func TestGenerateProfile_PTY(t *testing.T) {
	cfg := &Config{
		Command:   []string{"bash"},
		ProxyAddr: "127.0.0.1:8080",
		EnablePTY: true,
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	assert.Contains(t, profile, "(allow pseudo-tty)")
	assert.Contains(t, profile, "/dev/ptmx")
}

func TestGenerateProfile_NoPTY(t *testing.T) {
	cfg := &Config{
		Command:   []string{"echo"},
		ProxyAddr: "127.0.0.1:8080",
		EnablePTY: false,
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	assert.NotContains(t, profile, "(allow pseudo-tty)")
}
