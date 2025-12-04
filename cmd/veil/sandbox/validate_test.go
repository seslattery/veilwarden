package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidatePaths(t *testing.T) {
	// Create temp directory for valid path tests
	tmpDir := t.TempDir()
	validDir := filepath.Join(tmpDir, "valid")
	err := os.MkdirAll(validDir, 0755)
	require.NoError(t, err)

	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{
			name: "valid paths",
			cfg: &Config{
				Command:           []string{"test"},
				ProxyAddr:         "127.0.0.1:8080",
				AllowedWritePaths: []string{tmpDir, validDir},
			},
			wantErr: "",
		},
		{
			name: "nonexistent write path",
			cfg: &Config{
				Command:           []string{"test"},
				ProxyAddr:         "127.0.0.1:8080",
				AllowedWritePaths: []string{"/does/not/exist"},
			},
			wantErr: "path does not exist",
		},
		{
			name: "nonexistent read path",
			cfg: &Config{
				Command:          []string{"test"},
				ProxyAddr:        "127.0.0.1:8080",
				AllowedReadPaths: []string{"/also/does/not/exist"},
			},
			wantErr: "path does not exist",
		},
		{
			name: "denied read paths not validated for existence",
			cfg: &Config{
				Command:         []string{"test"},
				ProxyAddr:       "127.0.0.1:8080",
				DeniedReadPaths: []string{"/this/can/not/exist"},
			},
			wantErr: "", // Should not error - we don't validate denied paths exist
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePaths(tt.cfg)
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestIsSensitivePath(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "ssh directory",
			path: filepath.Join(home, ".ssh"),
			want: true,
		},
		{
			name: "aws directory",
			path: filepath.Join(home, ".aws"),
			want: true,
		},
		{
			name: "gcloud directory",
			path: filepath.Join(home, ".config/gcloud"),
			want: true,
		},
		{
			name: "etc passwd",
			path: "/etc/passwd",
			want: true,
		},
		{
			name: "etc shadow",
			path: "/etc/shadow",
			want: true,
		},
		{
			name: "subdirectory of sensitive",
			path: filepath.Join(home, ".ssh/keys"),
			want: true,
		},
		{
			name: "regular directory",
			path: "/tmp",
			want: false,
		},
		{
			name: "user project",
			path: filepath.Join(home, "projects"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSensitivePath(tt.path)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSuggestDeniedReadPaths(t *testing.T) {
	paths := SuggestDeniedReadPaths()
	assert.NotEmpty(t, paths)
	assert.Contains(t, paths, "~/.ssh")
	assert.Contains(t, paths, "~/.aws")
}
