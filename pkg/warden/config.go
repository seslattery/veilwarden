package warden

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// Config contains all settings needed to start a sandboxed process.
type Config struct {
	// Command to execute, e.g., ["python", "agent.py"]
	Command []string

	// Env is the environment variables to pass to the process.
	// Callers should seed this with os.Environ() if they want inherited env.
	Env []string

	// WorkingDir is the working directory for the command.
	WorkingDir string

	// ProxyAddr is the address of the MITM proxy (e.g., "127.0.0.1:8080").
	// The sandbox ONLY allows network access to this address.
	ProxyAddr string

	// AllowedWritePaths are paths the sandboxed process can write to.
	// Supports globs on macOS only (e.g., "/tmp/agent-*").
	AllowedWritePaths []string

	// DeniedReadPaths are paths the sandboxed process cannot read.
	// Supports globs on macOS only. Defaults applied if empty.
	DeniedReadPaths []string

	// AllowedReadPaths are additional paths the sandboxed process can read.
	// NOTE: Only supported by seatbelt backend. SRT backend ignores this field
	// (it allows reading all paths except DeniedReadPaths).
	AllowedReadPaths []string

	// AllowedHosts are domain names that the sandbox can make HTTP requests to.
	// Required for SRT backend. These should include all hosts from routes config
	// since SRT enforces domain-level restrictions even with httpProxyPort.
	AllowedHosts []string

	// AllowedUnixSockets are Unix socket paths the sandbox can access.
	// NOTE: Only supported by seatbelt backend. SRT backend ignores this field.
	// DANGEROUS: Only use if you understand the implications.
	AllowedUnixSockets []string

	// EnablePTY enables PTY allocation for interactive shells.
	EnablePTY bool

	// Debug enables verbose logging and disables seccomp (DANGEROUS).
	Debug bool
}

// DefaultDeniedReadPaths returns sensitive paths that should be blocked by default.
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
		"/etc/shadow",
		"/etc/sudoers",
	}
}

// Validate checks if the config is valid.
func (c *Config) Validate() error {
	if len(c.Command) == 0 {
		return fmt.Errorf("command is required")
	}
	if c.ProxyAddr == "" {
		return fmt.Errorf("proxy address is required for network isolation")
	}
	if err := validateProxyAddr(c.ProxyAddr); err != nil {
		return err
	}

	// Validate working directory
	if c.WorkingDir != "" && containsPathTraversal(c.WorkingDir) {
		return fmt.Errorf("working directory cannot contain path traversal: %s", c.WorkingDir)
	}

	// Debug mode is dangerous - require explicit opt-in
	if c.Debug {
		if os.Getenv("WARDEN_ALLOW_DEBUG") != "1" {
			return fmt.Errorf("debug mode requires WARDEN_ALLOW_DEBUG=1 environment variable")
		}
	}

	return nil
}

func validateProxyAddr(addr string) error {
	if addr == "" {
		return fmt.Errorf("proxy address is empty")
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid proxy address: %w", err)
	}

	// Allow localhost explicitly
	if host == "localhost" {
		return nil
	}

	// Must be a loopback IP (127.0.0.1, ::1, etc.)
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("proxy must be loopback address (localhost/127.0.0.1/::1), got: %s", addr)
	}

	return nil
}

func containsPathTraversal(path string) bool {
	return strings.Contains(path, "..")
}
