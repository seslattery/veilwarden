package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"veilwarden/internal/proxy"
)

func TestSandboxFlag_ReturnsError(t *testing.T) {
	// Save and restore original value
	originalSandbox := execSandbox
	defer func() { execSandbox = originalSandbox }()

	execSandbox = true

	cmd := &cobra.Command{}
	err := runExec(cmd, []string{"echo", "test"})

	if err == nil {
		t.Fatal("expected error when sandbox flag is set")
	}

	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Fatalf("expected 'not yet implemented' in error, got: %v", err)
	}
}

func TestBuildProxyEnv_StripsDopplerToken(t *testing.T) {
	parentEnv := []string{
		"DOPPLER_TOKEN=dp.st.dev.secret123",
		"OPENAI_API_KEY=sk-test",
		"PATH=/usr/bin",
		"HOME=/home/user",
	}

	childEnv := buildProxyEnv(parentEnv, "http://localhost:8080", "/tmp/ca.crt")

	// DOPPLER_TOKEN should be stripped
	for _, e := range childEnv {
		if strings.HasPrefix(e, "DOPPLER_TOKEN=") {
			t.Fatal("DOPPLER_TOKEN should not be in child environment")
		}
	}

	// Other secrets should remain
	hasOpenAI := false
	hasPath := false
	for _, e := range childEnv {
		if strings.HasPrefix(e, "OPENAI_API_KEY=") {
			hasOpenAI = true
		}
		if strings.HasPrefix(e, "PATH=") {
			hasPath = true
		}
	}
	if !hasOpenAI {
		t.Fatal("OPENAI_API_KEY should remain in child environment")
	}
	if !hasPath {
		t.Fatal("PATH should remain in child environment")
	}

	// Proxy vars should be added
	hasHTTPProxy := false
	for _, e := range childEnv {
		if strings.HasPrefix(e, "HTTP_PROXY=") {
			hasHTTPProxy = true
		}
	}
	if !hasHTTPProxy {
		t.Fatal("HTTP_PROXY should be added to child environment")
	}
}

func TestBuildPolicyEngine_RespectsConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       *veilConfig
		wantAllowAll bool
		wantErr      bool
	}{
		{
			name:         "disabled returns allow-all",
			config:       &veilConfig{Policy: &veilPolicyEntry{Engine: "disabled"}},
			wantAllowAll: true,
		},
		{
			name:         "empty returns allow-all for backward compatibility",
			config:       &veilConfig{},
			wantAllowAll: true,
		},
		{
			name:    "unknown engine returns error",
			config:  &veilConfig{Policy: &veilPolicyEntry{Engine: "invalid"}},
			wantErr: true,
		},
		{
			name:    "opa engine without policy path returns error",
			config:  &veilConfig{Policy: &veilPolicyEntry{Engine: "opa"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := buildPolicyEngine(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error for invalid engine")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if engine == nil {
				t.Fatal("expected policy engine, got nil")
			}

			// Type check for allow-all
			_, isAllowAll := engine.(*proxy.AllowAllPolicyEngine)
			if tt.wantAllowAll && !isAllowAll {
				t.Fatalf("expected AllowAllPolicyEngine, got %T", engine)
			}
			if !tt.wantAllowAll && isAllowAll {
				t.Fatal("expected non-AllowAll engine, got AllowAllPolicyEngine")
			}
		})
	}
}
