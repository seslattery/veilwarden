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
	// Command to execute, e.g., ["python", "agent.py"]
	Command []string

	// Environment variables to pass to the process
	Env []string

	// WorkingDir is the working directory for the command
	WorkingDir string

	// ProxyAddr is the address of the MITM proxy (e.g., "127.0.0.1:8080")
	// The sandbox will be configured to ONLY allow network access to this address,
	// forcing all traffic through the proxy.
	ProxyAddr string

	// AllowedHosts are the target hosts that can be accessed through the proxy.
	// This is needed for srt's domain filtering - it filters CONNECT targets too.
	// Policy enforcement is still handled by the MITM proxy's OPA engine.
	AllowedHosts []string

	// AllowedWritePaths are host paths the sandboxed process can write to.
	// Uses allowlist model - writes are denied everywhere except these paths.
	AllowedWritePaths []string

	// DeniedReadPaths are host paths the sandboxed process cannot read.
	// Use for sensitive directories like ~/.ssh, ~/.aws, etc.
	DeniedReadPaths []string

	// AllowedReadPaths are additional host paths the sandboxed process can read.
	// By default, most system paths are readable; use DeniedReadPaths to restrict.
	AllowedReadPaths []string
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

	if c.ProxyAddr == "" {
		return fmt.Errorf("proxy address is required for network isolation")
	}

	// Validate paths are absolute or ~-prefixed
	for i, p := range c.AllowedWritePaths {
		if !isValidPath(p) {
			return fmt.Errorf("allowed_write_paths[%d]: invalid path: %s", i, p)
		}
	}

	for i, p := range c.DeniedReadPaths {
		if !isValidPath(p) {
			return fmt.Errorf("denied_read_paths[%d]: invalid path: %s", i, p)
		}
	}

	for i, p := range c.AllowedReadPaths {
		if !isValidPath(p) {
			return fmt.Errorf("allowed_read_paths[%d]: invalid path: %s", i, p)
		}
	}

	return nil
}

// isValidPath checks if a path is valid (absolute or ~-prefixed)
func isValidPath(path string) bool {
	if path == "" {
		return false
	}
	// Allow absolute paths, ~-prefixed paths, or relative paths (will be resolved)
	return filepath.IsAbs(path) || path[0] == '~' || path[0] == '.'
}

// DefaultDeniedReadPaths returns the default list of sensitive paths to deny reading
func DefaultDeniedReadPaths() []string {
	return []string{
		"~/.ssh",
		"~/.aws",
		"~/.config/gcloud",
		"~/.azure",
		"~/.doppler",
		"~/.gnupg",
		"~/.kube",
		"~/.docker",
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
	}
}
