package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/seslattery/veilwarden/pkg/warden"
)

// Config represents the veil CLI configuration.
type Config struct {
	Routes  []RouteEntry  `yaml:"routes"`
	Policy  *PolicyEntry  `yaml:"policy,omitempty"`
	Doppler *DopplerEntry `yaml:"doppler,omitempty"`
	Sandbox *SandboxEntry `yaml:"sandbox,omitempty"`
	Proxy   *ProxyEntry   `yaml:"proxy,omitempty"`

	// configDir is the directory containing the config file.
	// Used for resolving relative paths.
	configDir string
}

// RouteEntry configures credential injection for a specific host.
type RouteEntry struct {
	Host                string `yaml:"host"`
	SecretID            string `yaml:"secret_id"`
	HeaderName          string `yaml:"header_name"`
	HeaderValueTemplate string `yaml:"header_value_template"`
}

// PolicyEntry configures request authorization.
type PolicyEntry struct {
	Engine       string `yaml:"engine"`
	PolicyPath   string `yaml:"policy_path"`
	DecisionPath string `yaml:"decision_path"`
}

// DopplerEntry configures Doppler secret store.
type DopplerEntry struct {
	Project  string `yaml:"project"`
	Config   string `yaml:"config"`
	CacheTTL string `yaml:"cache_ttl,omitempty"` // e.g., "5m", "1h"
}

// SandboxEntry configures sandbox isolation.
type SandboxEntry struct {
	Enabled           bool     `yaml:"enabled"`
	Backend           string   `yaml:"backend"`
	WorkingDir        string   `yaml:"working_dir,omitempty"`
	AllowedWritePaths []string `yaml:"allowed_write_paths,omitempty"`
	DeniedReadPaths   []string `yaml:"denied_read_paths,omitempty"`
	// AllowedReadPaths: TODO not yet implemented in seatbelt. Workaround: use
	// AllowedWritePaths instead (write paths get read access for dotfiles).
	AllowedReadPaths []string `yaml:"allowed_read_paths,omitempty"`
	EnvPassthrough   []string `yaml:"env_passthrough,omitempty"`
	EnablePTY        bool     `yaml:"enable_pty,omitempty"`
}

// ProxyEntry configures proxy behavior.
type ProxyEntry struct {
	TimeoutSeconds int `yaml:"timeout_seconds,omitempty"` // default: 300 (5 minutes)
}

// Load reads and parses a configuration file.
func Load(path string) (*Config, error) {
	// Expand home directory
	path = warden.ExpandPath(path)

	// Get absolute path to track config directory
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve config path: %w", err)
	}

	// #nosec G304 -- Config path comes from CLI flag
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Track config directory for path resolution
	cfg.configDir = filepath.Dir(absPath)

	// Resolve all relative paths to be relative to config directory
	cfg.resolvePaths()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// ConfigDir returns the directory containing the config file.
func (c *Config) ConfigDir() string {
	return c.configDir
}

// resolvePaths converts all relative paths in the config to absolute paths
// relative to the config directory.
func (c *Config) resolvePaths() {
	// Resolve policy path
	if c.Policy != nil && c.Policy.PolicyPath != "" {
		c.Policy.PolicyPath = c.resolvePath(c.Policy.PolicyPath)
	}

	// Resolve sandbox paths
	if c.Sandbox != nil {
		// WorkingDir is special: if not specified, it uses cwd (not config dir)
		// Only resolve if explicitly set
		if c.Sandbox.WorkingDir != "" {
			c.Sandbox.WorkingDir = c.resolvePath(c.Sandbox.WorkingDir)
		}

		// Resolve write paths
		for i, p := range c.Sandbox.AllowedWritePaths {
			c.Sandbox.AllowedWritePaths[i] = c.resolvePath(p)
		}

		// Resolve read paths
		for i, p := range c.Sandbox.AllowedReadPaths {
			c.Sandbox.AllowedReadPaths[i] = c.resolvePath(p)
		}

		// Resolve denied read paths
		for i, p := range c.Sandbox.DeniedReadPaths {
			c.Sandbox.DeniedReadPaths[i] = c.resolvePath(p)
		}
	}
}

// resolvePath resolves a path relative to the config directory.
// - Paths starting with / are absolute (unchanged)
// - Paths starting with ~ are home-relative (expanded)
// - Paths starting with ./ or ../ are config-relative
// - Bare paths are config-relative
func (c *Config) resolvePath(path string) string {
	// Expand home directory first
	path = warden.ExpandPath(path)

	// Already absolute after expansion
	if filepath.IsAbs(path) {
		return path
	}

	// Relative path - resolve against config directory
	return filepath.Join(c.configDir, path)
}

// Default returns a Config with sensible defaults.
// Sandbox is enabled by default with auto backend and PTY support.
func Default() *Config {
	return &Config{
		Sandbox: &SandboxEntry{
			Enabled:   true,
			Backend:   "auto",
			EnablePTY: true,
		},
	}
}

// ApplyDefaults fills in default values for unset fields.
func (c *Config) ApplyDefaults() {
	// Apply sandbox defaults if not configured
	if c.Sandbox == nil {
		c.Sandbox = &SandboxEntry{
			Enabled:   true,
			Backend:   "auto",
			EnablePTY: true,
		}
	} else {
		// Apply individual defaults if sandbox exists but fields are empty
		if c.Sandbox.Backend == "" {
			c.Sandbox.Backend = "auto"
		}
	}
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	// Validate Doppler configuration if present
	if c.Doppler != nil {
		if c.Doppler.Project == "" {
			return fmt.Errorf("doppler.project is required when doppler section is present")
		}
		if c.Doppler.Config == "" {
			return fmt.Errorf("doppler.config is required when doppler section is present")
		}
		// Validate cache_ttl if provided
		if c.Doppler.CacheTTL != "" {
			if _, err := time.ParseDuration(c.Doppler.CacheTTL); err != nil {
				return fmt.Errorf("invalid doppler.cache_ttl: %w", err)
			}
		}
	}

	// Validate Sandbox configuration if present
	if c.Sandbox != nil && c.Sandbox.Enabled {
		if c.Sandbox.Backend == "" {
			return fmt.Errorf("sandbox.backend is required when sandbox is enabled")
		}

		// Validate backend is known
		if !warden.ValidBackends[c.Sandbox.Backend] {
			return fmt.Errorf("unknown sandbox backend: %s", c.Sandbox.Backend)
		}
	}

	// Validate route configurations
	for i, route := range c.Routes {
		if route.Host == "" {
			return fmt.Errorf("routes[%d]: host is required", i)
		}
		if route.SecretID == "" {
			return fmt.Errorf("routes[%d]: secret_id is required", i)
		}
		if route.HeaderName == "" {
			return fmt.Errorf("routes[%d]: header_name is required", i)
		}
		if !strings.Contains(route.HeaderValueTemplate, "{{secret}}") {
			return fmt.Errorf("routes[%d]: header_value_template must contain {{secret}}", i)
		}
	}

	return nil
}

// GetProxyTimeout returns the configured proxy timeout in seconds.
// Returns 300 (5 minutes) as default if not configured.
func (c *Config) GetProxyTimeout() int {
	if c.Proxy != nil && c.Proxy.TimeoutSeconds > 0 {
		return c.Proxy.TimeoutSeconds
	}
	return 300 // 5 minutes default
}
