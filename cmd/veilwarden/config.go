package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type fileConfig struct {
	Routes  []routeEntry  `yaml:"routes"`
	Secrets []secretEntry `yaml:"secrets"`
	Policy  *policyEntry  `yaml:"policy"`
}

type policyEntry struct {
	Enabled      bool   `yaml:"enabled"`
	DefaultAllow bool   `yaml:"default_allow"`
	Engine       string `yaml:"engine"`        // "config" or "opa"
	PolicyPath   string `yaml:"policy_path"`   // path to .rego files (for opa engine)
	DecisionPath string `yaml:"decision_path"` // OPA query path (default: veilwarden/authz/allow)
}

type routeEntry struct {
	UpstreamHost        string `yaml:"upstream_host"`
	UpstreamScheme      string `yaml:"upstream_scheme"`
	SecretID            string `yaml:"secret_id"`
	InjectHeader        string `yaml:"inject_header"`
	HeaderValueTemplate string `yaml:"header_value_template"`
}

type secretEntry struct {
	ID    string `yaml:"id"`
	Value string `yaml:"value"`
}

type appConfig struct {
	routes  map[string]route
	secrets map[string]string
	policy  policyConfig
}

func loadAppConfig(path string) (*appConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return parseConfig(data)
}

func parseConfig(data []byte) (*appConfig, error) {
	var raw fileConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	secretMap := make(map[string]string, len(raw.Secrets))
	for _, s := range raw.Secrets {
		if s.ID == "" {
			return nil, errors.New("config: secret id cannot be empty")
		}
		if _, exists := secretMap[s.ID]; exists {
			return nil, fmt.Errorf("config: duplicate secret id %q", s.ID)
		}
		secretMap[s.ID] = s.Value
	}

	routeMap := make(map[string]route, len(raw.Routes))
	for _, r := range raw.Routes {
		if err := validateRoute(r); err != nil {
			return nil, err
		}
		key := strings.ToLower(r.UpstreamHost)
		if _, exists := routeMap[key]; exists {
			return nil, fmt.Errorf("config: duplicate route for host %q", r.UpstreamHost)
		}

		scheme := r.UpstreamScheme
		if scheme == "" {
			scheme = "https"
		}

		routeMap[key] = route{
			upstreamHost:        r.UpstreamHost,
			upstreamScheme:      scheme,
			secretID:            r.SecretID,
			headerName:          r.InjectHeader,
			headerValueTemplate: r.HeaderValueTemplate,
		}
	}

	// Parse policy configuration (optional section)
	policyCfg := policyConfig{
		Enabled:      false,
		DefaultAllow: true, // default to allow for backwards compatibility
		Engine:       "config",
		PolicyPath:   "",
		DecisionPath: "veilwarden/authz/allow", // default OPA decision path
	}
	if raw.Policy != nil {
		policyCfg.Enabled = raw.Policy.Enabled
		policyCfg.DefaultAllow = raw.Policy.DefaultAllow
		if raw.Policy.Engine != "" {
			policyCfg.Engine = raw.Policy.Engine
		}
		if raw.Policy.PolicyPath != "" {
			policyCfg.PolicyPath = raw.Policy.PolicyPath
		}
		if raw.Policy.DecisionPath != "" {
			policyCfg.DecisionPath = raw.Policy.DecisionPath
		}
	}

	return &appConfig{
		routes:  routeMap,
		secrets: secretMap,
		policy:  policyCfg,
	}, nil
}

func validateRoute(r routeEntry) error {
	if r.UpstreamHost == "" {
		return errors.New("config: route upstream_host is required")
	}
	if strings.Contains(r.UpstreamHost, "/") {
		return fmt.Errorf("config: upstream_host %q must not include path", r.UpstreamHost)
	}
	if r.SecretID == "" {
		return fmt.Errorf("config: route %q secret_id is required", r.UpstreamHost)
	}
	if r.InjectHeader == "" {
		return fmt.Errorf("config: route %q inject_header is required", r.UpstreamHost)
	}
	if r.HeaderValueTemplate == "" {
		return fmt.Errorf("config: route %q header_value_template is required", r.UpstreamHost)
	}
	if !strings.Contains(r.HeaderValueTemplate, "{{secret}}") {
		return fmt.Errorf("config: route %q header_value_template must contain {{secret}}", r.UpstreamHost)
	}
	return nil
}
