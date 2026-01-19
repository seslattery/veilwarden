package allowlist

import (
	"context"
	"testing"

	"github.com/seslattery/veilwarden/internal/proxy"
)

func TestEngine_Decide_ExactHost(t *testing.T) {
	engine, err := New([]Rule{
		{Host: "api.openai.com"},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	tests := []struct {
		name    string
		host    string
		allowed bool
	}{
		{"exact match", "api.openai.com", true},
		{"no match", "api.anthropic.com", false},
		{"partial no match", "openai.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.Decide(context.Background(), &proxy.PolicyInput{
				UpstreamHost: tt.host,
				Method:       "GET",
				Path:         "/v1/chat",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision.Allowed != tt.allowed {
				t.Errorf("got allowed=%v, want %v", decision.Allowed, tt.allowed)
			}
		})
	}
}

func TestEngine_Decide_WildcardHost(t *testing.T) {
	engine, err := New([]Rule{
		{Host: "*.githubusercontent.com"},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	tests := []struct {
		name    string
		host    string
		allowed bool
	}{
		{"wildcard match", "raw.githubusercontent.com", true},
		{"wildcard match 2", "objects.githubusercontent.com", true},
		{"no match base", "githubusercontent.com", false},
		{"no match other", "github.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.Decide(context.Background(), &proxy.PolicyInput{
				UpstreamHost: tt.host,
				Method:       "GET",
				Path:         "/",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision.Allowed != tt.allowed {
				t.Errorf("got allowed=%v, want %v", decision.Allowed, tt.allowed)
			}
		})
	}
}

func TestEngine_Decide_MethodRestriction(t *testing.T) {
	engine, err := New([]Rule{
		{Host: "api.github.com", Methods: []string{"GET"}},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	tests := []struct {
		name    string
		method  string
		allowed bool
	}{
		{"allowed method", "GET", true},
		{"blocked method", "POST", false},
		{"blocked method 2", "DELETE", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.Decide(context.Background(), &proxy.PolicyInput{
				UpstreamHost: "api.github.com",
				Method:       tt.method,
				Path:         "/repos",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision.Allowed != tt.allowed {
				t.Errorf("got allowed=%v, want %v", decision.Allowed, tt.allowed)
			}
		})
	}
}

func TestEngine_Decide_PathRestriction(t *testing.T) {
	engine, err := New([]Rule{
		{Host: "api.stripe.com", Paths: []string{"/v1/customers/*", "/v1/invoices/*"}},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		allowed bool
	}{
		{"allowed path", "/v1/customers/cus_123", true},
		{"allowed path 2", "/v1/invoices/inv_456", true},
		{"blocked path", "/v1/charges", false},
		{"blocked path 2", "/v1/refunds/re_789", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.Decide(context.Background(), &proxy.PolicyInput{
				UpstreamHost: "api.stripe.com",
				Method:       "GET",
				Path:         tt.path,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision.Allowed != tt.allowed {
				t.Errorf("got allowed=%v, want %v", decision.Allowed, tt.allowed)
			}
		})
	}
}

func TestPreset_AICodingAgent(t *testing.T) {
	rules, err := GetPreset("ai-coding-agent")
	if err != nil {
		t.Fatalf("GetPreset failed: %v", err)
	}

	engine, err := New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Should allow AI APIs
	allowed := []string{"api.openai.com", "api.anthropic.com", "api.github.com"}
	for _, host := range allowed {
		decision, _ := engine.Decide(context.Background(), &proxy.PolicyInput{
			UpstreamHost: host,
			Method:       "POST",
			Path:         "/v1/chat",
		})
		if !decision.Allowed {
			t.Errorf("expected %s to be allowed", host)
		}
	}

	// Should block random hosts
	decision, _ := engine.Decide(context.Background(), &proxy.PolicyInput{
		UpstreamHost: "evil.com",
		Method:       "POST",
		Path:         "/",
	})
	if decision.Allowed {
		t.Error("expected evil.com to be blocked")
	}
}

func TestPreset_Unknown(t *testing.T) {
	_, err := GetPreset("unknown-preset")
	if err == nil {
		t.Error("expected error for unknown preset")
	}
}
