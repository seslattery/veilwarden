package warden

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
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
	// AllowWrite paths - writes denied everywhere except these (required by srt, even if empty)
	AllowWrite []string `json:"allowWrite"`
	// DenyRead paths - reads blocked for these paths (required by srt, even if empty)
	DenyRead []string `json:"denyRead"`
	// DenyWrite paths within allowed paths (required by srt, even if empty)
	DenyWrite []string `json:"denyWrite"`
}

// SrtBackend implements sandbox using the Anthropic srt CLI.
type SrtBackend struct {
	cliPath string // Path to srt binary
}

// NewSrtBackend creates a new SRT backend, checking if srt is available.
func NewSrtBackend() (*SrtBackend, error) {
	// Check if srt CLI exists
	cliPath, err := exec.LookPath("srt")
	if err != nil {
		return nil, fmt.Errorf(
			"srt CLI not found in PATH.\n\n" +
				"To install:\n" +
				"  npm install -g @anthropic-ai/sandbox-runtime\n\n" +
				"Alternatively, use native sandbox (macOS only):\n" +
				"  veil exec --sandbox --backend=seatbelt")
	}
	return &SrtBackend{cliPath: cliPath}, nil
}

// Start launches the sandboxed process using srt.
func (s *SrtBackend) Start(ctx context.Context, cfg *Config) (*Process, error) {
	// Validate config first
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create temporary settings file
	settingsFile, err := s.createSettingsFile(cfg)
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

	cmd := exec.CommandContext(ctx, s.cliPath, args...)

	// Set working directory if specified
	if cfg.WorkingDir != "" {
		cmd.Dir = ExpandPath(cfg.WorkingDir)
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
		return nil, fmt.Errorf("failed to start srt: %w", err)
	}

	return &Process{
		PID:    cmd.Process.Pid,
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		Wait: func() error {
			// Close stdin first (safe even if already closed)
			_ = stdin.Close()
			err := cmd.Wait()
			// Clean up settings file after process exits
			os.Remove(settingsFile)
			return err
		},
	}, nil
}

// createSettingsFile generates a temporary srt settings JSON file.
func (s *SrtBackend) createSettingsFile(cfg *Config) (string, error) {
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

		// Build allowed domains list from config
		// SRT requires explicit allowedDomains even with httpProxyPort
		// Include: proxy host (localhost/127.0.0.1) + all route hosts from config
		// Note: SRT doesn't accept IPv6 (::1) as a valid domain pattern
		allowedDomains := []string{"localhost", "127.0.0.1"}
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			allowedDomains = append(allowedDomains, host)
		}
		for _, h := range cfg.AllowedHosts {
			// Skip IPv6 addresses which SRT doesn't accept
			if h != "::1" && h != "" {
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
	// AllowWrite, DenyRead, and DenyWrite are required by srt, even if empty
	settings.Filesystem = srtFilesystemSettings{
		AllowWrite: []string{}, // Required field
		DenyRead:   []string{}, // Required field
		DenyWrite:  []string{}, // Required field
	}

	// Expand and add allowed write paths
	if len(cfg.AllowedWritePaths) > 0 {
		settings.Filesystem.AllowWrite = make([]string, len(cfg.AllowedWritePaths))
		for i, p := range cfg.AllowedWritePaths {
			settings.Filesystem.AllowWrite[i] = ExpandPath(p)
		}
	}

	// Expand and add denied read paths
	if len(cfg.DeniedReadPaths) > 0 {
		settings.Filesystem.DenyRead = make([]string, len(cfg.DeniedReadPaths))
		for i, p := range cfg.DeniedReadPaths {
			settings.Filesystem.DenyRead[i] = ExpandPath(p)
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
