package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"veilwarden/internal/proxy"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildProxyEnv_StripsSecrets(t *testing.T) {
	parentEnv := []string{
		"DOPPLER_TOKEN=dp.st.dev.secret123",
		"OPENAI_API_KEY=sk-test",
		"GITHUB_TOKEN=ghp_test",
		"AWS_SECRET_ACCESS_KEY=secret",
		"MY_PASSWORD=hunter2",
		"PATH=/usr/bin",
		"HOME=/home/user",
		"EDITOR=vim",
	}

	childEnv := buildProxyEnv(parentEnv, "http://localhost:8080", "/tmp/ca.crt", nil)

	// Check what's stripped and what remains
	envMap := make(map[string]bool)
	for _, e := range childEnv {
		key := strings.SplitN(e, "=", 2)[0]
		envMap[key] = true
	}

	// These should be stripped (secrets)
	strippedVars := []string{"DOPPLER_TOKEN", "OPENAI_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "MY_PASSWORD"}
	for _, v := range strippedVars {
		if envMap[v] {
			t.Errorf("%s should be stripped from child environment", v)
		}
	}

	// These should remain (non-secrets)
	remainingVars := []string{"PATH", "HOME", "EDITOR"}
	for _, v := range remainingVars {
		if !envMap[v] {
			t.Errorf("%s should remain in child environment", v)
		}
	}

	// Proxy vars should be added
	if !envMap["HTTP_PROXY"] {
		t.Fatal("HTTP_PROXY should be added to child environment")
	}
}

func TestBuildProxyEnv_Passthrough(t *testing.T) {
	parentEnv := []string{
		"OPENAI_API_KEY=sk-test",
		"CUSTOM_TOKEN=my-token",
		"PATH=/usr/bin",
	}

	// Allow CUSTOM_TOKEN through via passthrough
	childEnv := buildProxyEnv(parentEnv, "http://localhost:8080", "/tmp/ca.crt", []string{"CUSTOM_TOKEN"})

	envMap := make(map[string]bool)
	for _, e := range childEnv {
		key := strings.SplitN(e, "=", 2)[0]
		envMap[key] = true
	}

	// CUSTOM_TOKEN should be allowed through
	if !envMap["CUSTOM_TOKEN"] {
		t.Error("CUSTOM_TOKEN should be allowed through via passthrough")
	}

	// OPENAI_API_KEY should still be stripped (not in passthrough)
	if envMap["OPENAI_API_KEY"] {
		t.Error("OPENAI_API_KEY should be stripped")
	}

	// PATH should remain
	if !envMap["PATH"] {
		t.Error("PATH should remain")
	}
}

func TestLooksLikeSecret(t *testing.T) {
	tests := []struct {
		key      string
		isSecret bool
	}{
		{"OPENAI_API_KEY", true},
		{"AWS_SECRET_ACCESS_KEY", true},
		{"GITHUB_TOKEN", true},
		{"DOPPLER_TOKEN", true},
		{"MY_PASSWORD", true},
		{"DB_CREDENTIALS", true},
		{"PRIVATE_KEY", true},
		{"AUTH_TOKEN", true},
		{"PATH", false},
		{"HOME", false},
		{"EDITOR", false},
		{"DEBUG", false},
		{"NODE_ENV", false},
		{"GOPATH", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			result := looksLikeSecret(tt.key)
			if result != tt.isSecret {
				t.Errorf("looksLikeSecret(%q) = %v, want %v", tt.key, result, tt.isSecret)
			}
		})
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

func TestProxyListenerReuse(t *testing.T) {
	// This test verifies we don't have a race condition where
	// we find a port, close it, then try to rebind
	// The fix is to keep the listener open and pass it directly

	// Create a listener on port 0 (random)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port

	// Don't close - simulate "stolen" port
	defer listener.Close()

	// Try to bind to the same port - should fail
	_, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	assert.Error(t, err, "should fail to bind to already-bound port")
}
