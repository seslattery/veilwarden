package main

import "testing"

func TestParseConfigSuccess(t *testing.T) {
	data := []byte(`
secrets:
  - id: stripe
    value: sk_test
routes:
  - upstream_host: api.stripe.com
    secret_id: stripe
    inject_header: Authorization
    header_value_template: "Bearer {{secret}}"
`)
	cfg, err := parseConfig(data)
	if err != nil {
		t.Fatalf("parseConfig error: %v", err)
	}

	route, ok := cfg.routes["api.stripe.com"]
	if !ok {
		t.Fatalf("route for api.stripe.com missing")
	}
	if route.upstreamScheme != "https" {
		t.Fatalf("expected https scheme, got %s", route.upstreamScheme)
	}
	if route.headerName != "Authorization" {
		t.Fatalf("unexpected header name %s", route.headerName)
	}
	if cfg.secrets["stripe"] != "sk_test" {
		t.Fatalf("secret value not populated")
	}
}

func TestParseConfigMissingSecret(t *testing.T) {
	data := []byte(`
routes:
  - upstream_host: api.example.com
    secret_id: missing
    inject_header: Authorization
    header_value_template: "Bearer {{secret}}"
`)
	cfg, err := parseConfig(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.routes["api.example.com"].secretID != "missing" {
		t.Fatalf("secret id not preserved")
	}
	if len(cfg.secrets) != 0 {
		t.Fatalf("expected no secrets")
	}
}

func TestParseConfigMissingTemplate(t *testing.T) {
	data := []byte(`
routes:
  - upstream_host: api.example.com
    secret_id: test
    inject_header: Authorization
`)
	_, err := parseConfig(data)
	if err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestParseConfigWithOPAPolicy(t *testing.T) {
	yaml := `
routes:
  - upstream_host: api.example.com
    upstream_scheme: https
    secret_id: TEST_SECRET
    inject_header: Authorization
    header_value_template: "Bearer {{secret}}"
policy:
  enabled: true
  engine: opa
  policy_path: policies/
  decision_path: veilwarden/authz/allow
`

	cfg, err := parseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	if !cfg.policy.Enabled {
		t.Error("expected policy enabled")
	}
	if cfg.policy.Engine != "opa" {
		t.Errorf("expected engine 'opa', got %s", cfg.policy.Engine)
	}
	if cfg.policy.PolicyPath != "policies/" {
		t.Errorf("expected policy_path 'policies/', got %s", cfg.policy.PolicyPath)
	}
	if cfg.policy.DecisionPath != "veilwarden/authz/allow" {
		t.Errorf("expected decision_path 'veilwarden/authz/allow', got %s", cfg.policy.DecisionPath)
	}
}

func TestParseConfigInvalidEngine(t *testing.T) {
	yaml := `
routes:
  - upstream_host: api.example.com
    upstream_scheme: https
    secret_id: TEST_SECRET
    inject_header: Authorization
    header_value_template: "Bearer {{secret}}"
policy:
  enabled: true
  engine: invalid
`

	cfg, err := parseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("config parsing should succeed: %v", err)
	}

	// Config parsing succeeds, but buildPolicyEngine will fail
	// This is tested in main_test.go
	if cfg.policy.Engine != "invalid" {
		t.Errorf("expected engine 'invalid', got %s", cfg.policy.Engine)
	}
}

func TestParseConfigBackwardsCompatibility(t *testing.T) {
	// Old config without engine field should default to "config"
	yaml := `
routes:
  - upstream_host: api.example.com
    upstream_scheme: https
    secret_id: TEST_SECRET
    inject_header: Authorization
    header_value_template: "Bearer {{secret}}"
policy:
  enabled: true
  default_allow: false
`

	cfg, err := parseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	if cfg.policy.Engine != "config" {
		t.Errorf("expected default engine 'config', got %s", cfg.policy.Engine)
	}
	if cfg.policy.Enabled != true {
		t.Error("expected policy enabled")
	}
	if cfg.policy.DefaultAllow != false {
		t.Error("expected default_allow false")
	}
}

func TestParseConfigWithKubernetes(t *testing.T) {
	yaml := `
routes:
  - upstream_host: api.example.com
    upstream_scheme: https
    secret_id: TEST_SECRET
    inject_header: Authorization
    header_value_template: "Bearer {{secret}}"
kubernetes:
  enabled: "true"
  api_server: "https://my-k8s-api.example.com"
  token_path: "/custom/path/to/token"
  validate_method: "tokenreview"
`

	cfg, err := parseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	if cfg.kubernetes.enabled != "true" {
		t.Errorf("expected enabled 'true', got %s", cfg.kubernetes.enabled)
	}
	if cfg.kubernetes.apiServer != "https://my-k8s-api.example.com" {
		t.Errorf("expected api_server 'https://my-k8s-api.example.com', got %s", cfg.kubernetes.apiServer)
	}
	if cfg.kubernetes.tokenPath != "/custom/path/to/token" {
		t.Errorf("expected token_path '/custom/path/to/token', got %s", cfg.kubernetes.tokenPath)
	}
	if cfg.kubernetes.validateMethod != "tokenreview" {
		t.Errorf("expected validate_method 'tokenreview', got %s", cfg.kubernetes.validateMethod)
	}
}

func TestParseConfigKubernetesDefaults(t *testing.T) {
	// Test that kubernetes config has proper defaults when not specified
	yaml := `
routes:
  - upstream_host: api.example.com
    upstream_scheme: https
    secret_id: TEST_SECRET
    inject_header: Authorization
    header_value_template: "Bearer {{secret}}"
`

	cfg, err := parseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	// Should have default values
	if cfg.kubernetes.enabled != "auto" {
		t.Errorf("expected default enabled 'auto', got %s", cfg.kubernetes.enabled)
	}
	if cfg.kubernetes.apiServer != "https://kubernetes.default.svc" {
		t.Errorf("expected default api_server 'https://kubernetes.default.svc', got %s", cfg.kubernetes.apiServer)
	}
	if cfg.kubernetes.tokenPath != "/var/run/secrets/kubernetes.io/serviceaccount/token" {
		t.Errorf("expected default token_path '/var/run/secrets/kubernetes.io/serviceaccount/token', got %s", cfg.kubernetes.tokenPath)
	}
	if cfg.kubernetes.validateMethod != "tokenreview" {
		t.Errorf("expected default validate_method 'tokenreview', got %s", cfg.kubernetes.validateMethod)
	}
}

func TestParseConfigKubernetesPartialOverride(t *testing.T) {
	// Test that only specified kubernetes fields are overridden
	yaml := `
routes:
  - upstream_host: api.example.com
    upstream_scheme: https
    secret_id: TEST_SECRET
    inject_header: Authorization
    header_value_template: "Bearer {{secret}}"
kubernetes:
  enabled: "false"
`

	cfg, err := parseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	if cfg.kubernetes.enabled != "false" {
		t.Errorf("expected enabled 'false', got %s", cfg.kubernetes.enabled)
	}
	// Other fields should have defaults
	if cfg.kubernetes.apiServer != "https://kubernetes.default.svc" {
		t.Errorf("expected default api_server, got %s", cfg.kubernetes.apiServer)
	}
	if cfg.kubernetes.tokenPath != "/var/run/secrets/kubernetes.io/serviceaccount/token" {
		t.Errorf("expected default token_path, got %s", cfg.kubernetes.tokenPath)
	}
	if cfg.kubernetes.validateMethod != "tokenreview" {
		t.Errorf("expected default validate_method, got %s", cfg.kubernetes.validateMethod)
	}
}
