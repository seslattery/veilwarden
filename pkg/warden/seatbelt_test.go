//go:build darwin

package warden

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeatbeltBackend_Start(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("skipping seatbelt test in CI")
	}

	backend := &SeatbeltBackend{}

	cfg := &Config{
		Command:   []string{"echo", "hello"},
		ProxyAddr: "127.0.0.1:8080",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proc, err := backend.Start(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, proc)

	err = proc.Wait()
	assert.NoError(t, err)
}

func TestSeatbeltBackend_FilesystemIsolation(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("skipping seatbelt test in CI")
	}

	backend := &SeatbeltBackend{}

	tmpDir := t.TempDir()
	// Resolve symlinks to match what seatbelt expects (e.g., /var -> /private/var)
	realTmpDir, err := filepath.EvalSymlinks(tmpDir)
	require.NoError(t, err)

	secretFile := filepath.Join(tmpDir, "secret.txt")
	err = os.WriteFile(secretFile, []byte("secret"), 0644)
	require.NoError(t, err)

	cfg := &Config{
		Command:         []string{"cat", secretFile},
		ProxyAddr:       "127.0.0.1:8080",
		DeniedReadPaths: []string{realTmpDir},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proc, err := backend.Start(ctx, cfg)
	require.NoError(t, err)

	// Read stderr in background
	stderrChan := make(chan string)
	go func() {
		data, _ := io.ReadAll(proc.Stderr)
		stderrChan <- string(data)
	}()

	// Should fail because path is denied
	err = proc.Wait()
	stderr := <-stderrChan

	// Command should fail with permission denied
	require.Error(t, err, "expected command to fail when reading denied path")
	assert.Contains(t, stderr, "Operation not permitted", "expected permission denied error in stderr")
}
