package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Simplified config types for veil CLI
type veilConfig struct {
	Routes  []veilRouteEntry   `yaml:"routes"`
	Policy  *veilPolicyEntry   `yaml:"policy,omitempty"`
	Doppler *veilDopplerEntry  `yaml:"doppler,omitempty"`
	Sandbox *veilSandboxEntry  `yaml:"sandbox,omitempty"`
}

type veilRouteEntry struct {
	Host                string `yaml:"host"`
	SecretID            string `yaml:"secret_id"`
	HeaderName          string `yaml:"header_name"`
	HeaderValueTemplate string `yaml:"header_value_template"`
}

type veilPolicyEntry struct {
	Enabled         bool   `yaml:"enabled"`
	Engine          string `yaml:"engine"`
	PolicyPath      string `yaml:"policy_path"`
	DecisionPath    string `yaml:"decision_path"`
	DefaultDecision string `yaml:"default_decision"` // "allow" or "deny"
}

type veilDopplerEntry struct {
	Project  string `yaml:"project"`
	Config   string `yaml:"config"`
	CacheTTL string `yaml:"cache_ttl,omitempty"` // e.g., "5m", "1h"
}

type veilSandboxEntry struct {
	Enabled    bool             `yaml:"enabled"`
	Backend    string           `yaml:"backend"`
	WorkingDir string           `yaml:"working_dir,omitempty"`
	Mounts     []veilMountEntry `yaml:"mounts,omitempty"`
}

type veilMountEntry struct {
	HostPath      string `yaml:"host"`
	ContainerPath string `yaml:"container"`
	ReadOnly      bool   `yaml:"readonly"`
}

func loadVeilConfig(path string) (*veilConfig, error) {
	// Expand home directory
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err == nil {
			path = strings.Replace(path, "~", home, 1)
		}
	}

	// #nosec G304 -- Config path comes from CLI flag
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg veilConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Validate Doppler configuration if present
	if cfg.Doppler != nil {
		if cfg.Doppler.Project == "" {
			return nil, fmt.Errorf("doppler.project is required when doppler section is present")
		}
		if cfg.Doppler.Config == "" {
			return nil, fmt.Errorf("doppler.config is required when doppler section is present")
		}
		// Validate cache_ttl if provided
		if cfg.Doppler.CacheTTL != "" {
			if _, err := time.ParseDuration(cfg.Doppler.CacheTTL); err != nil {
				return nil, fmt.Errorf("invalid doppler.cache_ttl: %w", err)
			}
		}
	}

	// Validate Sandbox configuration if present
	if cfg.Sandbox != nil && cfg.Sandbox.Enabled {
		if cfg.Sandbox.Backend == "" {
			return nil, fmt.Errorf("sandbox.backend is required when sandbox is enabled")
		}

		// Validate backend is known
		validBackends := map[string]bool{
			"anthropic": true,
			// Future: "gvisor", "firecracker", etc.
		}
		if !validBackends[cfg.Sandbox.Backend] {
			return nil, fmt.Errorf("unknown sandbox backend: %s (available: anthropic)", cfg.Sandbox.Backend)
		}

		// Validate mounts
		for i, mount := range cfg.Sandbox.Mounts {
			if mount.HostPath == "" {
				return nil, fmt.Errorf("sandbox.mounts[%d]: mount host path is required", i)
			}
			if mount.ContainerPath == "" {
				return nil, fmt.Errorf("sandbox.mounts[%d]: mount container path is required", i)
			}
		}
	}

	return &cfg, nil
}
