package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Simplified config types for veil CLI
type veilConfig struct {
	Routes []veilRouteEntry `yaml:"routes"`
	Policy *veilPolicyEntry `yaml:"policy"`
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

	return &cfg, nil
}
