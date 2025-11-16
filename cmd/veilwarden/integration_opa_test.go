package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOPAIntegrationAllowed(t *testing.T) {
	// Create temporary policy
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test.rego")

	policy := `package veilwarden.authz
import rego.v1
default allow := false

allow if {
    input.method == "GET"
    input.agent_id == "test-agent"
}

allow if {
    input.user_org == "engineering"
}`

	if err := os.WriteFile(policyFile, []byte(policy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	// Create OPA policy engine
	engine, err := newOPAPolicyEngine(context.Background(), policyConfig{
		Enabled:      true,
		Engine:       "opa",
		PolicyPath:   tmpDir,
		DecisionPath: "veilwarden/authz/allow",
	})
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	// Create proxy server with OPA engine
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

	server := newProxyServer(routes, "session", &configSecretStore{
		secrets: map[string]string{"test-secret": "secret-value"},
	}, nil, engine, nil, "alice", "alice@company.com", "engineering")

	server.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
	}

	// Test allowed request (engineering user)
	req := httptest.NewRequest(http.MethodPost, "http://veilwarden/test", nil)
	req.Header.Set(sessionHeader, "session")
	req.Header.Set(upstreamHeader, host)
	req.Header.Set("X-Agent-Id", "other-agent")

	rec := httptest.NewRecorder()
	server.handleHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestOPAIntegrationDenied(t *testing.T) {
	// Create temporary policy with restrictive rules
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test.rego")

	policy := `package veilwarden.authz
import rego.v1
default allow := false

allow if {
    input.method == "GET"
    input.user_org == "engineering"
}`

	if err := os.WriteFile(policyFile, []byte(policy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	engine, err := newOPAPolicyEngine(context.Background(), policyConfig{
		Enabled:      true,
		Engine:       "opa",
		PolicyPath:   tmpDir,
		DecisionPath: "veilwarden/authz/allow",
	})
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}
	defer engine.Close()

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

	server := newProxyServer(routes, "session", &configSecretStore{
		secrets: map[string]string{"test-secret": "secret-value"},
	}, nil, engine, nil, "bob", "bob@company.com", "external")

	// Test denied request (POST from external user)
	req := httptest.NewRequest(http.MethodPost, "http://veilwarden/admin", nil)
	req.Header.Set(sessionHeader, "session")
	req.Header.Set(upstreamHeader, host)
	req.Header.Set("X-Agent-Id", "unknown-agent")

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

	if !strings.Contains(payload.Message, "denied by OPA policy") {
		t.Fatalf("unexpected error message: %s", payload.Message)
	}
}
