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
