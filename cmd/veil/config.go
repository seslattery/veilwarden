package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"veilwarden/pkg/warden"
)

// Simplified config types for veil CLI
type veilConfig struct {
	Routes  []veilRouteEntry  `yaml:"routes"`
	Policy  *veilPolicyEntry  `yaml:"policy,omitempty"`
	Doppler *veilDopplerEntry `yaml:"doppler,omitempty"`
	Sandbox *veilSandboxEntry `yaml:"sandbox,omitempty"`
}

type veilRouteEntry struct {
	Host                string `yaml:"host"`
	SecretID            string `yaml:"secret_id"`
	HeaderName          string `yaml:"header_name"`
	HeaderValueTemplate string `yaml:"header_value_template"`
}

type veilPolicyEntry struct {
	Engine       string `yaml:"engine"`
	PolicyPath   string `yaml:"policy_path"`
	DecisionPath string `yaml:"decision_path"`
}

type veilDopplerEntry struct {
	Project  string `yaml:"project"`
	Config   string `yaml:"config"`
	CacheTTL string `yaml:"cache_ttl,omitempty"` // e.g., "5m", "1h"
}

type veilSandboxEntry struct {
	Enabled           bool     `yaml:"enabled"`
	Backend           string   `yaml:"backend"`
	WorkingDir        string   `yaml:"working_dir,omitempty"`
	AllowedWritePaths []string `yaml:"allowed_write_paths,omitempty"`
	DeniedReadPaths   []string `yaml:"denied_read_paths,omitempty"`
	AllowedReadPaths  []string `yaml:"allowed_read_paths,omitempty"`
}

func loadVeilConfig(path string) (*veilConfig, error) {
	// Expand home directory
	path = warden.ExpandPath(path)

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
		if !warden.ValidBackends[cfg.Sandbox.Backend] {
			return nil, fmt.Errorf("unknown sandbox backend: %s", cfg.Sandbox.Backend)
		}
	}

	// Validate route configurations
	for i, route := range cfg.Routes {
		if route.Host == "" {
			return nil, fmt.Errorf("routes[%d]: host is required", i)
		}
		if route.SecretID == "" {
			return nil, fmt.Errorf("routes[%d]: secret_id is required", i)
		}
		if route.HeaderName == "" {
			return nil, fmt.Errorf("routes[%d]: header_name is required", i)
		}
		if !strings.Contains(route.HeaderValueTemplate, "{{secret}}") {
			return nil, fmt.Errorf("routes[%d]: header_value_template must contain {{secret}}", i)
		}
	}

	return &cfg, nil
}
