package main

import (
	"os"
	"strings"
	"testing"

	"veilwarden/internal/proxy"

	"github.com/spf13/cobra"
)

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

func TestVeilExec_UsesPolicyFromConfig(t *testing.T) {
	// This test verifies that when a config with policy is loaded,
	// the policy engine is actually used (not hardcoded allow-all)

	// Note: This is a light integration test. Full policy enforcement
	// is tested in internal/proxy tests. Here we just verify wiring.

	// Create temp config with deny-by-default policy
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"
	configContent := `
routes:
  - host: api.test.com
    secret_id: TEST_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

policy:
  engine: opa
  policy_path: /tmp/test.rego
  decision_path: veilwarden/authz/allow
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Load config
	cfg, err := loadVeilConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Build policy engine - should fail because policy file doesn't exist
	// But that's expected - we're just verifying it tries to use OPA
	_, err = buildPolicyEngine(cfg)
	if err == nil {
		t.Fatal("expected error when OPA policy file doesn't exist")
	}

	// Verify error is about the policy file, not about using wrong engine
	if !strings.Contains(err.Error(), "policy_path") && !strings.Contains(err.Error(), "rego") {
		t.Fatalf("expected error about policy file, got: %v", err)
	}
}

func TestShouldUseSandbox(t *testing.T) {
	tests := []struct {
		name           string
		configEnabled  bool
		sandboxFlag    bool
		noSandboxFlag  bool
		expectedResult bool
	}{
		{
			name:           "config enabled, no flags",
			configEnabled:  true,
			sandboxFlag:    false,
			noSandboxFlag:  false,
			expectedResult: true,
		},
		{
			name:           "config disabled, no flags",
			configEnabled:  false,
			sandboxFlag:    false,
			noSandboxFlag:  false,
			expectedResult: false,
		},
		{
			name:           "config enabled, --no-sandbox flag",
			configEnabled:  true,
			sandboxFlag:    false,
			noSandboxFlag:  true,
			expectedResult: false,
		},
		{
			name:           "config disabled, --sandbox flag",
			configEnabled:  false,
			sandboxFlag:    true,
			noSandboxFlag:  false,
			expectedResult: true,
		},
		{
			name:           "--sandbox overrides config",
			configEnabled:  false,
			sandboxFlag:    true,
			noSandboxFlag:  false,
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &veilConfig{}
			if tt.configEnabled {
				cfg.Sandbox = &veilSandboxEntry{
					Enabled: true,
					Backend: "anthropic",
				}
			}

			// Mock command with flags
			cmd := &cobra.Command{}
			cmd.Flags().Bool("sandbox", false, "")
			cmd.Flags().Bool("no-sandbox", false, "")

			if tt.sandboxFlag {
				cmd.Flags().Set("sandbox", "true")
			}
			if tt.noSandboxFlag {
				cmd.Flags().Set("no-sandbox", "true")
			}

			result := shouldUseSandbox(cfg, cmd)
			if result != tt.expectedResult {
				t.Errorf("shouldUseSandbox() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}
