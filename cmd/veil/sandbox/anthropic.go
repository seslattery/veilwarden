package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// srtSettings represents the JSON configuration for srt
type srtSettings struct {
	Network    srtNetworkSettings    `json:"network,omitempty"`
	Filesystem srtFilesystemSettings `json:"filesystem,omitempty"`
}

type srtNetworkSettings struct {
	// AllowedDomains whitelist - only these can be accessed
	AllowedDomains []string `json:"allowedDomains,omitempty"`
	// DeniedDomains blacklist - required by srt even if empty
	DeniedDomains []string `json:"deniedDomains"`
	// HTTPProxyPort tells srt to use an external HTTP proxy instead of starting its own.
	// When set, srt skips starting its internal proxy and routes all traffic through this port.
	// This allows us to force all sandbox traffic through our MITM proxy for credential injection.
	HTTPProxyPort int `json:"httpProxyPort,omitempty"`
}

type srtFilesystemSettings struct {
	// AllowWrite paths - writes denied everywhere except these
	AllowWrite []string `json:"allowWrite,omitempty"`
	// DenyRead paths - reads blocked for these paths
	DenyRead []string `json:"denyRead,omitempty"`
	// DenyWrite paths within allowed paths (required by srt, even if empty)
	DenyWrite []string `json:"denyWrite"`
}

// AnthropicBackend implements sandbox using the Anthropic srt CLI
type AnthropicBackend struct {
	cliPath string // Path to srt binary
}

// NewAnthropicBackend creates a new Anthropic sandbox backend
func NewAnthropicBackend() (*AnthropicBackend, error) {
	// Check if srt CLI exists
	cliPath, err := exec.LookPath("srt")
	if err != nil {
		return nil, fmt.Errorf(
			"srt CLI not found in PATH.\n\n" +
				"To install:\n" +
				"  1. Visit: https://github.com/anthropic-experimental/sandbox-runtime\n" +
				"  2. Follow installation instructions\n" +
				"  3. Verify: srt --version\n\n" +
				"Alternatively, disable sandboxing:\n" +
				"  - Use flag: veil exec --no-sandbox\n" +
				"  - Or in config: sandbox.enabled: false")
	}

	return &AnthropicBackend{cliPath: cliPath}, nil
}

// Start launches the sandboxed process
func (a *AnthropicBackend) Start(ctx context.Context, cfg *Config) (*Process, error) {
	// Validate config first
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create temporary settings file
	settingsFile, err := a.createSettingsFile(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create settings file: %w", err)
	}

	// When using httpProxyPort, wrap command with env -u to clear NO_PROXY.
	// srt sets NO_PROXY=localhost,127.0.0.1,... to prevent proxy loops, but our
	// proxy runs outside the sandbox, so we need localhost traffic proxied too.
	command := cfg.Command
	if cfg.ProxyAddr != "" {
		command = append([]string{"env", "-u", "NO_PROXY", "-u", "no_proxy"}, command...)
	}

	// Build command arguments
	args := []string{"--settings", settingsFile}
	args = append(args, command...)

	cmd := exec.CommandContext(ctx, a.cliPath, args...)

	// Set working directory if specified
	if cfg.WorkingDir != "" {
		cmd.Dir = expandPath(cfg.WorkingDir)
	}

	// Set environment variables (srt inherits from parent)
	cmd.Env = cfg.Env

	// Setup stdio pipes
	stdin, err := cmd.StdinPipe()
	if err != nil {
		os.Remove(settingsFile)
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		os.Remove(settingsFile)
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		os.Remove(settingsFile)
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the sandbox process
	if err := cmd.Start(); err != nil {
		os.Remove(settingsFile)
		return nil, fmt.Errorf("failed to start sandbox: %w", err)
	}

	return &Process{
		PID:    cmd.Process.Pid,
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		Wait: func() error {
			err := cmd.Wait()
			stdin.Close()
			// Clean up settings file after process exits
			os.Remove(settingsFile)
			return err
		},
	}, nil
}

// createSettingsFile generates a temporary srt settings JSON file
func (a *AnthropicBackend) createSettingsFile(cfg *Config) (string, error) {
	settings := srtSettings{}

	// Configure network isolation with httpProxyPort
	// By setting httpProxyPort, we tell srt to use our external MITM proxy instead of its own.
	// This ensures ALL sandbox traffic flows through our proxy for credential injection and OPA policy.
	if cfg.ProxyAddr != "" {
		// Extract host and port from ProxyAddr
		host, portStr, err := net.SplitHostPort(cfg.ProxyAddr)
		if err != nil {
			// Maybe it's just a host without port - use default HTTP proxy port
			host = cfg.ProxyAddr
			portStr = "8080"
		}

		proxyPort, err := strconv.Atoi(portStr)
		if err != nil {
			return "", fmt.Errorf("invalid proxy port: %s", portStr)
		}

		// Build allowed domains list
		// With httpProxyPort, srt routes traffic through our proxy, but may still filter at sandbox level.
		// Include proxy host and all target hosts. Policy enforcement is handled by our MITM proxy + OPA.
		allowedDomains := []string{host, "localhost", "127.0.0.1"}
		for _, h := range cfg.AllowedHosts {
			// Avoid duplicates
			duplicate := false
			for _, existing := range allowedDomains {
				if existing == h {
					duplicate = true
					break
				}
			}
			if !duplicate {
				allowedDomains = append(allowedDomains, h)
			}
		}

		settings.Network = srtNetworkSettings{
			AllowedDomains: allowedDomains,
			DeniedDomains:  []string{}, // Required by srt
			HTTPProxyPort:  proxyPort,  // Route all traffic through our MITM proxy
		}
	}

	// Configure filesystem access
	// DenyWrite is required by srt, even if empty
	settings.Filesystem = srtFilesystemSettings{
		DenyWrite: []string{}, // Required field
	}

	// Expand and add allowed write paths
	if len(cfg.AllowedWritePaths) > 0 {
		settings.Filesystem.AllowWrite = make([]string, len(cfg.AllowedWritePaths))
		for i, p := range cfg.AllowedWritePaths {
			settings.Filesystem.AllowWrite[i] = expandPath(p)
		}
	}

	// Expand and add denied read paths
	if len(cfg.DeniedReadPaths) > 0 {
		settings.Filesystem.DenyRead = make([]string, len(cfg.DeniedReadPaths))
		for i, p := range cfg.DeniedReadPaths {
			settings.Filesystem.DenyRead[i] = expandPath(p)
		}
	}

	// Create temp file for settings
	tmpFile, err := os.CreateTemp("", "veil-srt-settings-*.json")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	// Write settings as JSON
	encoder := json.NewEncoder(tmpFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(settings); err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to write settings: %w", err)
	}

	return tmpFile.Name(), nil
}

// expandPath expands ~ to home directory
func expandPath(path string) string {
	if path == "" {
		return path
	}

	if path[0] == '~' {
		home, err := os.UserHomeDir()
		if err == nil {
			// Replace only the leading ~
			if len(path) == 1 {
				return home
			}
			if path[1] == '/' {
				return filepath.Join(home, path[2:])
			}
		}
	}

	return path
}
