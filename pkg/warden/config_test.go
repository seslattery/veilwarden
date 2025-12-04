package warden

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate_RequiresCommand(t *testing.T) {
	cfg := &Config{
		ProxyAddr: "127.0.0.1:8080",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "command")
}

func TestConfig_Validate_RequiresProxyAddr(t *testing.T) {
	cfg := &Config{
		Command: []string{"echo", "hello"},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "proxy")
}

func TestConfig_Validate_ValidConfig(t *testing.T) {
	cfg := &Config{
		Command:   []string{"echo", "hello"},
		ProxyAddr: "127.0.0.1:8080",
	}
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestValidateProxyAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"localhost:8080", "localhost:8080", false},
		{"127.0.0.1:8080", "127.0.0.1:8080", false},
		{"::1 with port", "[::1]:8080", false},
		{"external host", "example.com:8080", true},
		{"external IP", "10.0.0.1:8080", true},
		{"missing port", "localhost", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProxyAddr(tt.addr)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDefaultDeniedReadPaths(t *testing.T) {
	paths := DefaultDeniedReadPaths()
	assert.Contains(t, paths, "~/.ssh")
	assert.Contains(t, paths, "~/.aws")
	assert.Contains(t, paths, "~/.gnupg")
	assert.True(t, len(paths) >= 8, "should have at least 8 default denied paths")
}

func TestConfig_Validate_DebugRequiresEnvVar(t *testing.T) {
	cfg := &Config{
		Command:   []string{"echo"},
		ProxyAddr: "127.0.0.1:8080",
		Debug:     true,
	}

	// Without env var, should fail
	t.Setenv("WARDEN_ALLOW_DEBUG", "")
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WARDEN_ALLOW_DEBUG")

	// With env var, should pass
	t.Setenv("WARDEN_ALLOW_DEBUG", "1")
	err = cfg.Validate()
	assert.NoError(t, err)
}

func TestConfig_Validate_WorkingDir(t *testing.T) {
	tests := []struct {
		name       string
		workingDir string
		wantErr    bool
	}{
		{"normal path", "/tmp/work", false},
		{"home path", "~/project", false},
		{"path traversal", "/tmp/../etc/passwd", true},
		{"embedded traversal", "/tmp/foo/../../../etc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Command:    []string{"echo", "test"},
				ProxyAddr:  "127.0.0.1:8080",
				WorkingDir: tt.workingDir,
			}
			err := cfg.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
