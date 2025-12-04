package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{
			name: "valid config",
			cfg: &Config{
				Command:           []string{"python", "test.py"},
				Env:               []string{"PATH=/usr/bin"},
				WorkingDir:        "/workspace",
				ProxyAddr:         "127.0.0.1:8080",
				AllowedWritePaths: []string{"/workspace", "/tmp/data"},
				DeniedReadPaths:   []string{"~/.ssh", "~/.aws"},
			},
			wantErr: "",
		},
		{
			name: "empty command",
			cfg: &Config{
				Command:   []string{},
				Env:       []string{},
				ProxyAddr: "127.0.0.1:8080",
			},
			wantErr: "command is required",
		},
		{
			name: "missing proxy address",
			cfg: &Config{
				Command: []string{"test"},
			},
			wantErr: "proxy address is required",
		},
		{
			name: "invalid write path",
			cfg: &Config{
				Command:           []string{"test"},
				ProxyAddr:         "127.0.0.1:8080",
				AllowedWritePaths: []string{""},
			},
			wantErr: "allowed_write_paths[0]: invalid path",
		},
		{
			name: "invalid denied read path",
			cfg: &Config{
				Command:         []string{"test"},
				ProxyAddr:       "127.0.0.1:8080",
				DeniedReadPaths: []string{""},
			},
			wantErr: "denied_read_paths[0]: invalid path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestDefaultDeniedReadPaths(t *testing.T) {
	paths := DefaultDeniedReadPaths()
	assert.NotEmpty(t, paths)
	assert.Contains(t, paths, "~/.ssh")
	assert.Contains(t, paths, "~/.aws")
	assert.Contains(t, paths, "~/.doppler")
}

func TestIsValidPath(t *testing.T) {
	tests := []struct {
		path  string
		valid bool
	}{
		{"/absolute/path", true},
		{"~/home/path", true},
		{"./relative/path", true},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := isValidPath(tt.path)
			assert.Equal(t, tt.valid, result)
		})
	}
}
