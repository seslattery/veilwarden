package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfigPolicyEngineDisabled(t *testing.T) {
	engine := newConfigPolicyEngine(policyConfig{
		Enabled:      false,
		DefaultAllow: false, // Even though default is deny, disabled policy should allow
	})

	input := PolicyInput{
		Method:       "POST",
		Path:         "/test",
		UpstreamHost: "api.example.com",
		AgentID:      "test-agent",
	}

	decision, err := engine.Decide(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Allowed {
		t.Fatal("expected allow when policy disabled")
	}
	if decision.Reason != "policy enforcement disabled" {
		t.Fatalf("unexpected reason: %s", decision.Reason)
	}
}

func TestConfigPolicyEngineAllowByDefault(t *testing.T) {
	engine := newConfigPolicyEngine(policyConfig{
		Enabled:      true,
		DefaultAllow: true,
	})

	input := PolicyInput{
		Method:       "GET",
		Path:         "/users",
		UpstreamHost: "api.github.com",
		AgentID:      "cli-tool",
	}

	decision, err := engine.Decide(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Allowed {
		t.Fatal("expected allow when default_allow is true")
	}
	if decision.Reason != "allowed by default policy" {
		t.Fatalf("unexpected reason: %s", decision.Reason)
	}
}

func TestConfigPolicyEngineDenyByDefault(t *testing.T) {
	engine := newConfigPolicyEngine(policyConfig{
		Enabled:      true,
		DefaultAllow: false,
	})

	input := PolicyInput{
		Method:       "DELETE",
		Path:         "/admin",
		UpstreamHost: "api.stripe.com",
		AgentID:      "unknown-agent",
	}

	decision, err := engine.Decide(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Allowed {
		t.Fatal("expected deny when default_allow is false")
	}
	if decision.Reason != "denied by default policy" {
		t.Fatalf("unexpected reason: %s", decision.Reason)
	}
}

func TestProxyPolicyAllowed(t *testing.T) {
	host := "api.test"
	routes := map[string]route{
		strings.ToLower(host): {
			upstreamHost:        host,
			upstreamScheme:      "http",
			secretID:            "test-secret",
			headerName:          "Authorization",
			headerValueTemplate: "Bearer {{secret}}",
		},
	}

	// Policy engine that allows all requests
	policyEngine := newConfigPolicyEngine(policyConfig{
		Enabled:      true,
		DefaultAllow: true,
	})

	server := newProxyServer(routes, "session", &configSecretStore{
		secrets: map[string]string{"test-secret": "secret-value"},
	}, nil, policyEngine, nil, "user123", "user@example.com", "engineering")

	server.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodGet, "http://veilwarden/test", nil)
	req.Header.Set(sessionHeader, "session")
	req.Header.Set(upstreamHeader, host)
	req.Header.Set("X-Agent-Id", "test-agent")

	rec := httptest.NewRecorder()
	server.handleHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestProxyPolicyDenied(t *testing.T) {
	host := "api.test"
	routes := map[string]route{
		strings.ToLower(host): {
			upstreamHost:        host,
			upstreamScheme:      "http",
			secretID:            "test-secret",
			headerName:          "Authorization",
			headerValueTemplate: "Bearer {{secret}}",
		},
	}

	// Policy engine that denies all requests
	policyEngine := newConfigPolicyEngine(policyConfig{
		Enabled:      true,
		DefaultAllow: false,
	})

	server := newProxyServer(routes, "session", &configSecretStore{
		secrets: map[string]string{"test-secret": "secret-value"},
	}, nil, policyEngine, nil, "user456", "blocked@example.com", "external")

	req := httptest.NewRequest(http.MethodDelete, "http://veilwarden/admin", nil)
	req.Header.Set(sessionHeader, "session")
	req.Header.Set(upstreamHeader, host)
	req.Header.Set("X-Agent-Id", "blocked-agent")

	rec := httptest.NewRecorder()
	server.handleHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", resp.StatusCode)
	}

	var payload errorResponse
	if err := decodeJSON(resp.Body, &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if payload.Error != "POLICY_DENIED" {
		t.Fatalf("expected error POLICY_DENIED, got %s", payload.Error)
	}

	if !strings.Contains(payload.Message, "Policy denied request") {
		t.Fatalf("unexpected error message: %s", payload.Message)
	}
}

func TestPolicyInputContext(t *testing.T) {
	// This test verifies that the policy engine receives the correct context
	var capturedInput PolicyInput

	mockEngine := &mockPolicyEngine{
		decideFunc: func(ctx context.Context, input PolicyInput) (PolicyDecision, error) {
			capturedInput = input
			return PolicyDecision{Allowed: true, Reason: "mock allow"}, nil
		},
	}

	host := "api.github.com"
	routes := map[string]route{
		strings.ToLower(host): {
			upstreamHost:        host,
			upstreamScheme:      "https",
			secretID:            "github-token",
			headerName:          "Authorization",
			headerValueTemplate: "token {{secret}}",
		},
	}

	server := newProxyServer(routes, "session", &configSecretStore{
		secrets: map[string]string{"github-token": "ghp_test"},
	}, nil, mockEngine, nil, "alice", "alice@company.com", "engineering")

	server.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "http://veilwarden/repos/test?page=1", nil)
	req.Header.Set(sessionHeader, "session")
	req.Header.Set(upstreamHeader, host)
	req.Header.Set("X-Agent-Id", "ci-agent")

	rec := httptest.NewRecorder()
	server.handleHTTP(rec, req)

	// Verify policy input received all context
	if capturedInput.Method != "POST" {
		t.Errorf("expected method POST, got %s", capturedInput.Method)
	}
	if capturedInput.Path != "/repos/test" {
		t.Errorf("expected path /repos/test, got %s", capturedInput.Path)
	}
	if capturedInput.Query != "page=1" {
		t.Errorf("expected query page=1, got %s", capturedInput.Query)
	}
	if capturedInput.UpstreamHost != host {
		t.Errorf("expected upstream %s, got %s", host, capturedInput.UpstreamHost)
	}
	if capturedInput.AgentID != "ci-agent" {
		t.Errorf("expected agent_id ci-agent, got %s", capturedInput.AgentID)
	}
	if capturedInput.UserID != "alice" {
		t.Errorf("expected user_id alice, got %s", capturedInput.UserID)
	}
	if capturedInput.UserEmail != "alice@company.com" {
		t.Errorf("expected user_email alice@company.com, got %s", capturedInput.UserEmail)
	}
	if capturedInput.UserOrg != "engineering" {
		t.Errorf("expected user_org engineering, got %s", capturedInput.UserOrg)
	}
	if capturedInput.RequestID == "" {
		t.Error("expected request_id to be set")
	}
	if capturedInput.Timestamp.IsZero() {
		t.Error("expected timestamp to be set")
	}
}

func TestParseConfigWithPolicy(t *testing.T) {
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

	if !cfg.policy.Enabled {
		t.Error("expected policy enabled")
	}
	if cfg.policy.DefaultAllow {
		t.Error("expected policy default_allow to be false")
	}
}

func TestParseConfigWithoutPolicy(t *testing.T) {
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

	// Defaults: disabled and allow
	if cfg.policy.Enabled {
		t.Error("expected policy disabled by default")
	}
	if !cfg.policy.DefaultAllow {
		t.Error("expected policy default_allow to be true by default")
	}
}

// Helper types and functions

type mockPolicyEngine struct {
	decideFunc func(context.Context, PolicyInput) (PolicyDecision, error)
}

func (m *mockPolicyEngine) Decide(ctx context.Context, input PolicyInput) (PolicyDecision, error) {
	return m.decideFunc(ctx, input)
}

func decodeJSON(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}
