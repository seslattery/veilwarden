package sandbox

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
)

// Backend defines the interface for sandbox implementations.
type Backend interface {
	// Start launches the sandboxed process
	// Returns a running process handle and error
	Start(ctx context.Context, config *Config) (*Process, error)
}

// Config contains all settings needed to start a sandboxed process.
type Config struct {
	Command    []string // e.g., ["python", "agent.py"]
	Env        []string // e.g., ["HTTP_PROXY=...", "PATH=..."]
	Mounts     []Mount  // Filesystem mounts
	WorkingDir string   // Working directory inside sandbox
}

// Mount represents a filesystem mount from host to container.
type Mount struct {
	HostPath      string
	ContainerPath string
	ReadOnly      bool
}

// String returns mount in docker-style format
func (m Mount) String() string {
	if m.ReadOnly {
		return fmt.Sprintf("%s:%s:ro", m.HostPath, m.ContainerPath)
	}
	return fmt.Sprintf("%s:%s", m.HostPath, m.ContainerPath)
}

// Process represents a running sandboxed process.
type Process struct {
	PID    int
	Stdin  io.WriteCloser
	Stdout io.Reader
	Stderr io.Reader
	Wait   func() error // Blocks until process exits
}

// Validate checks if the config is valid
func (c *Config) Validate() error {
	if len(c.Command) == 0 {
		return fmt.Errorf("command is required")
	}

	// Validate mounts
	for i, m := range c.Mounts {
		if m.ContainerPath != "" && !filepath.IsAbs(m.ContainerPath) {
			return fmt.Errorf("mount[%d]: container path must be absolute: %s", i, m.ContainerPath)
		}
	}

	return nil
}
