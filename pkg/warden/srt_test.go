package warden

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSrtBackend_Start(t *testing.T) {
	// Skip if srt not installed
	if _, err := exec.LookPath("srt"); err != nil {
		t.Skip("srt not installed")
	}

	backend, err := NewSrtBackend()
	require.NoError(t, err)

	cfg := &Config{
		Command:   []string{"echo", "hello"},
		ProxyAddr: "127.0.0.1:8080",
		Env:       os.Environ(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := backend.Start(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, proc)
	require.Greater(t, proc.PID, 0)

	// Read stdout
	output, err := io.ReadAll(proc.Stdout)
	require.NoError(t, err)

	err = proc.Wait()
	require.NoError(t, err)

	// Verify output
	require.Contains(t, string(output), "hello")
}

func TestSrtBackend_StartWithWorkingDir(t *testing.T) {
	// Skip if srt not installed
	if _, err := exec.LookPath("srt"); err != nil {
		t.Skip("srt not installed")
	}

	backend, err := NewSrtBackend()
	require.NoError(t, err)

	tmpDir := t.TempDir()

	cfg := &Config{
		Command:    []string{"pwd"},
		ProxyAddr:  "127.0.0.1:8080",
		WorkingDir: tmpDir,
		Env:        os.Environ(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := backend.Start(ctx, cfg)
	require.NoError(t, err)

	// Read stdout
	output, err := io.ReadAll(proc.Stdout)
	require.NoError(t, err)

	err = proc.Wait()
	require.NoError(t, err)

	// Verify working directory
	require.Contains(t, strings.TrimSpace(string(output)), tmpDir)
}

func TestSrtBackend_StartWithAllowedWritePaths(t *testing.T) {
	// Skip if srt not installed
	if _, err := exec.LookPath("srt"); err != nil {
		t.Skip("srt not installed")
	}

	backend, err := NewSrtBackend()
	require.NoError(t, err)

	tmpDir := t.TempDir()

	cfg := &Config{
		Command:           []string{"touch", tmpDir + "/test.txt"},
		ProxyAddr:         "127.0.0.1:8080",
		AllowedWritePaths: []string{tmpDir},
		Env:               os.Environ(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := backend.Start(ctx, cfg)
	require.NoError(t, err)

	err = proc.Wait()
	require.NoError(t, err)

	// Verify file was created (write access granted)
	_, err = os.Stat(tmpDir + "/test.txt")
	require.NoError(t, err, "file should have been created in allowed write path")
}

func TestSrtBackend_InvalidConfig(t *testing.T) {
	// Skip if srt not installed
	if _, err := exec.LookPath("srt"); err != nil {
		t.Skip("srt not installed")
	}

	backend, err := NewSrtBackend()
	require.NoError(t, err)

	tests := []struct {
		name      string
		cfg       *Config
		expectErr string
	}{
		{
			name: "missing command",
			cfg: &Config{
				ProxyAddr: "127.0.0.1:8080",
			},
			expectErr: "command is required",
		},
		{
			name: "missing proxy",
			cfg: &Config{
				Command: []string{"echo", "test"},
			},
			expectErr: "proxy address is required",
		},
		{
			name: "invalid proxy address",
			cfg: &Config{
				Command:   []string{"echo", "test"},
				ProxyAddr: "invalid",
			},
			expectErr: "invalid proxy address",
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := backend.Start(ctx, tt.cfg)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectErr)
		})
	}
}

func TestNewSrtBackend_NotInstalled(t *testing.T) {
	// Temporarily modify PATH to not include srt
	origPath := os.Getenv("PATH")
	defer os.Setenv("PATH", origPath)

	os.Setenv("PATH", "/nonexistent")

	_, err := NewSrtBackend()
	require.Error(t, err)
	require.Contains(t, err.Error(), "srt CLI not found")
	require.Contains(t, err.Error(), "npm install")
}

func TestSrtBackend_ExpandPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty path",
			input:    "",
			expected: "",
		},
		{
			name:     "absolute path",
			input:    "/tmp/test",
			expected: "/tmp/test",
		},
		{
			name:     "relative path",
			input:    "test/path",
			expected: "test/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandPath(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestSrtBackend_ExpandPathWithHome(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "tilde only",
			input:    "~",
			expected: home,
		},
		{
			name:     "tilde with path",
			input:    "~/.ssh",
			expected: home + "/.ssh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandPath(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}
