package allowlist_test

import (
	"context"
	"testing"

	"github.com/seslattery/veilwarden/internal/config"
	"github.com/seslattery/veilwarden/internal/policy/allowlist"
	"github.com/seslattery/veilwarden/internal/proxy"
)

func TestConfigToEngine(t *testing.T) {
	// Simulate what buildAllowlistEngine does
	cfg := &config.PolicyEntry{
		Engine: "allowlist",
		Allow: []config.AllowlistRule{
			{Host: "api.openai.com"},
			{Host: "api.github.com", Methods: []string{"GET"}},
		},
	}

	var rules []allowlist.Rule
	for _, r := range cfg.Allow {
		rules = append(rules, allowlist.Rule{
			Host:    r.Host,
			Methods: r.Methods,
			Paths:   r.Paths,
		})
	}

	engine, err := allowlist.New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Test OpenAI allowed
	decision, _ := engine.Decide(context.Background(), &proxy.PolicyInput{
		UpstreamHost: "api.openai.com",
		Method:       "POST",
		Path:         "/v1/chat/completions",
	})
	if !decision.Allowed {
		t.Error("OpenAI should be allowed")
	}

	// Test GitHub GET allowed
	decision, _ = engine.Decide(context.Background(), &proxy.PolicyInput{
		UpstreamHost: "api.github.com",
		Method:       "GET",
		Path:         "/repos/foo/bar",
	})
	if !decision.Allowed {
		t.Error("GitHub GET should be allowed")
	}

	// Test GitHub POST blocked
	decision, _ = engine.Decide(context.Background(), &proxy.PolicyInput{
		UpstreamHost: "api.github.com",
		Method:       "POST",
		Path:         "/repos/foo/bar",
	})
	if decision.Allowed {
		t.Error("GitHub POST should be blocked")
	}
}

func TestPresetPlusInlineRules(t *testing.T) {
	// Test combining preset with inline rules
	presetRules, err := allowlist.GetPreset("strict-openai-only")
	if err != nil {
		t.Fatalf("GetPreset failed: %v", err)
	}

	// Add inline rules on top of preset
	inlineRules := []allowlist.Rule{
		{Host: "internal.company.com"},
	}

	allRules := append(presetRules, inlineRules...)
	engine, err := allowlist.New(allRules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// OpenAI should be allowed (from preset)
	decision, _ := engine.Decide(context.Background(), &proxy.PolicyInput{
		UpstreamHost: "api.openai.com",
		Method:       "POST",
		Path:         "/v1/chat",
	})
	if !decision.Allowed {
		t.Error("OpenAI should be allowed from preset")
	}

	// Internal company host should be allowed (from inline)
	decision, _ = engine.Decide(context.Background(), &proxy.PolicyInput{
		UpstreamHost: "internal.company.com",
		Method:       "GET",
		Path:         "/api/data",
	})
	if !decision.Allowed {
		t.Error("internal.company.com should be allowed from inline rule")
	}

	// Random host should be blocked
	decision, _ = engine.Decide(context.Background(), &proxy.PolicyInput{
		UpstreamHost: "evil.com",
		Method:       "GET",
		Path:         "/",
	})
	if decision.Allowed {
		t.Error("evil.com should be blocked")
	}
}

func TestMethodCaseInsensitive(t *testing.T) {
	engine, err := allowlist.New([]allowlist.Rule{
		{Host: "api.example.com", Methods: []string{"get", "POST"}},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	tests := []struct {
		method  string
		allowed bool
	}{
		{"GET", true},
		{"get", true},
		{"Get", true},
		{"POST", true},
		{"post", true},
		{"DELETE", false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			decision, _ := engine.Decide(context.Background(), &proxy.PolicyInput{
				UpstreamHost: "api.example.com",
				Method:       tt.method,
				Path:         "/",
			})
			if decision.Allowed != tt.allowed {
				t.Errorf("method %s: got allowed=%v, want %v", tt.method, decision.Allowed, tt.allowed)
			}
		})
	}
}

func TestHostCaseInsensitive(t *testing.T) {
	// DNS hostnames are case-insensitive per RFC 1035
	engine, err := allowlist.New([]allowlist.Rule{
		{Host: "API.OpenAI.COM"},
		{Host: "*.GitHub.Com"},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	tests := []struct {
		host    string
		allowed bool
	}{
		// Exact host matching (various cases)
		{"api.openai.com", true},
		{"API.OPENAI.COM", true},
		{"Api.OpenAI.Com", true},

		// Wildcard host matching (various cases)
		{"raw.github.com", true},
		{"RAW.GITHUB.COM", true},
		{"Raw.GitHub.Com", true},

		// Non-matching hosts
		{"api.anthropic.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			decision, _ := engine.Decide(context.Background(), &proxy.PolicyInput{
				UpstreamHost: tt.host,
				Method:       "GET",
				Path:         "/",
			})
			if decision.Allowed != tt.allowed {
				t.Errorf("host %s: got allowed=%v, want %v", tt.host, decision.Allowed, tt.allowed)
			}
		})
	}
}
