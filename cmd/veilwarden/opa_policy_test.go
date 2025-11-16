package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOPAPolicyEngineAllowAll(t *testing.T) {
	// Create temporary policy directory
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "allow_all.rego")

	policy := `package veilwarden.authz
import rego.v1
default allow := true`

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

	decision, err := engine.Decide(context.Background(), PolicyInput{
		Method:       "DELETE",
		Path:         "/admin",
		UpstreamHost: "api.stripe.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Allowed {
		t.Fatal("expected allow with allow_all policy")
	}
}

func TestOPAPolicyEngineDenyByDefault(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "deny_default.rego")

	policy := `package veilwarden.authz
import rego.v1
default allow := false
allow if {
    input.method == "GET"
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

	// Test denied request
	decision, err := engine.Decide(context.Background(), PolicyInput{
		Method: "DELETE",
		Path:   "/admin",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected deny for DELETE request")
	}

	// Test allowed request
	decision, err = engine.Decide(context.Background(), PolicyInput{
		Method: "GET",
		Path:   "/users",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Allowed {
		t.Fatal("expected allow for GET request")
	}
}

func TestOPAPolicyEngineComplexRules(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "complex.rego")

	policy := `package veilwarden.authz
import rego.v1
default allow := false

allow if {
    input.method == "POST"
    input.upstream_host == "api.github.com"
    input.agent_id == "ci-agent"
}

allow if {
    input.user_org == "engineering"
    input.method != "DELETE"
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

	tests := []struct {
		name    string
		input   PolicyInput
		allowed bool
	}{
		{
			name: "ci-agent POST to GitHub",
			input: PolicyInput{
				Method:       "POST",
				UpstreamHost: "api.github.com",
				AgentID:      "ci-agent",
			},
			allowed: true,
		},
		{
			name: "engineering GET request",
			input: PolicyInput{
				Method:  "GET",
				UserOrg: "engineering",
			},
			allowed: true,
		},
		{
			name: "engineering DELETE denied",
			input: PolicyInput{
				Method:  "DELETE",
				UserOrg: "engineering",
			},
			allowed: false,
		},
		{
			name: "unknown agent denied",
			input: PolicyInput{
				Method:       "POST",
				UpstreamHost: "api.github.com",
				AgentID:      "unknown",
			},
			allowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.Decide(context.Background(), tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision.Allowed != tt.allowed {
				t.Errorf("expected allowed=%v, got %v (reason: %s)",
					tt.allowed, decision.Allowed, decision.Reason)
			}
		})
	}
}
