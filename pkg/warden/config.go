package warden

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
	// TODO: Not yet implemented in seatbelt profile generator. As a workaround,
	// add paths to AllowedWritePaths instead - write paths automatically get
	// read access via DotfileReadExceptions for home directory dotfiles.
	AllowedReadPaths []string

	// AllowedHosts are domain names that the sandbox can make HTTP requests to.
	// These should include all hosts from routes config.
	AllowedHosts []string

	// AllowedUnixSockets are Unix socket paths the sandbox can access.
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

	// Validate command executable exists and is a file
	if err := validateCommandPath(c.Command[0]); err != nil {
		return fmt.Errorf("invalid command: %w", err)
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

// validateCommandPath checks that the command exists and is executable.
// For absolute paths, it validates the file directly.
// For relative paths, it uses exec.LookPath to find the command in PATH.
func validateCommandPath(cmdPath string) error {
	var absPath string
	var err error

	if filepath.IsAbs(cmdPath) {
		absPath = cmdPath
	} else {
		// Try to find command in PATH
		absPath, err = exec.LookPath(cmdPath)
		if err != nil {
			return fmt.Errorf("command not found: %s", cmdPath)
		}
	}

	// Verify the file exists and is not a directory
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("command not found: %s", absPath)
		}
		return fmt.Errorf("cannot access command: %w", err)
	}

	if info.IsDir() {
		return fmt.Errorf("command is a directory: %s", absPath)
	}

	return nil
}
