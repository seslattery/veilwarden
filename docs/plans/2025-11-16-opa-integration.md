# OPA Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the MVP config-based policy engine with a production-ready Open Policy Agent (OPA) integration that evaluates Rego policies for authorization decisions.

**Architecture:** Implement an `opaPolicyEngine` that satisfies the existing `PolicyEngine` interface using the OPA v1 SDK. Load policies from filesystem (`.rego` files) with optional bundle support. Maintain backwards compatibility by keeping the config-based engine as default when no policy files are specified.

**Tech Stack:**
- OPA v1 SDK (`github.com/open-policy-agent/opa/v1/sdk`)
- Rego policy language
- Existing PolicyEngine interface (no breaking changes)

---

## Task 1: Add OPA SDK Dependency

**Files:**
- Modify: `go.mod`
- Modify: `go.sum` (auto-generated)

**Step 1: Add OPA v1 SDK dependency**

Run: `go get github.com/open-policy-agent/opa/v1/sdk@latest`

Expected: Dependency added to go.mod, go.sum updated

**Step 2: Verify dependency**

Run: `go mod tidy && go mod verify`

Expected: `all modules verified`

**Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "feat: add OPA v1 SDK dependency"
```

---

## Task 2: Create Example Policy Files

**Files:**
- Create: `policies/README.md`
- Create: `policies/example.rego`
- Create: `policies/allow_all.rego`

**Step 1: Create policies directory and documentation**

```bash
mkdir -p policies
```

Create `policies/README.md`:

```markdown
# Veilwarden Policy Files

This directory contains Rego policies evaluated by OPA for authorization decisions.

## Policy Decision Point

Policies must define a decision at path `veilwarden/authz/allow` that returns a boolean.

## Input Structure

Policies receive the following input:

```json
{
  "method": "GET",
  "path": "/repos/user/repo",
  "query": "page=1",
  "upstream_host": "api.github.com",
  "agent_id": "cli-tool",
  "user_id": "alice",
  "user_email": "alice@example.com",
  "user_org": "engineering",
  "request_id": "abc123",
  "timestamp": "2025-11-16T12:00:00Z"
}
```

## Examples

See `example.rego` and `allow_all.rego` for sample policies.
```

**Step 2: Create example policy with realistic rules**

Create `policies/example.rego`:

```rego
package veilwarden.authz

import rego.v1

# Default deny
default allow := false

# Allow GET requests for engineering users
allow if {
    input.method == "GET"
    input.user_org == "engineering"
}

# Allow POST to GitHub API for specific agents
allow if {
    input.method == "POST"
    input.upstream_host == "api.github.com"
    input.agent_id == "ci-agent"
}

# Allow all requests from admin users
allow if {
    endswith(input.user_email, "@admin.example.com")
}

# Deny DELETE operations on production hosts
allow if {
    input.method != "DELETE"
    input.upstream_host != "api.stripe.com"
}
```

**Step 3: Create permissive policy for testing**

Create `policies/allow_all.rego`:

```rego
package veilwarden.authz

import rego.v1

# Allow all requests (useful for testing OPA integration)
default allow := true
```

**Step 4: Commit**

```bash
git add policies/
git commit -m "feat: add example OPA policy files"
```

---

## Task 3: Extend Configuration for OPA

**Files:**
- Modify: `cmd/veilwarden/config.go:18-21`
- Modify: `cmd/veilwarden/config.go:39`
- Modify: `cmd/veilwarden/config.go:92-99`

**Step 1: Write failing test for OPA config parsing**

Add to `cmd/veilwarden/config_test.go` (create if doesn't exist):

```go
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/veilwarden -run TestParseConfigWithOPAPolicy -v`

Expected: FAIL with "unknown field" or similar for new config fields

**Step 3: Extend policyEntry struct**

Modify `cmd/veilwarden/config.go:18-21`:

```go
type policyEntry struct {
	Enabled      bool   `yaml:"enabled"`
	DefaultAllow bool   `yaml:"default_allow"`
	Engine       string `yaml:"engine"`        // "config" or "opa"
	PolicyPath   string `yaml:"policy_path"`   // path to .rego files (for opa engine)
	DecisionPath string `yaml:"decision_path"` // OPA query path (default: veilwarden/authz/allow)
}
```

**Step 4: Extend policyConfig struct**

Modify `cmd/veilwarden/config.go:39`:

```go
type policyConfig struct {
	Enabled      bool
	DefaultAllow bool
	Engine       string // "config" or "opa"
	PolicyPath   string
	DecisionPath string
}
```

**Step 5: Update config parsing with OPA defaults**

Modify `cmd/veilwarden/config.go:92-99`:

```go
// Parse policy configuration (optional section)
policyCfg := policyConfig{
	Enabled:      false,
	DefaultAllow: true, // default to allow for backwards compatibility
	Engine:       "config",
	PolicyPath:   "",
	DecisionPath: "veilwarden/authz/allow", // default OPA decision path
}
if raw.Policy != nil {
	policyCfg.Enabled = raw.Policy.Enabled
	policyCfg.DefaultAllow = raw.Policy.DefaultAllow
	if raw.Policy.Engine != "" {
		policyCfg.Engine = raw.Policy.Engine
	}
	if raw.Policy.PolicyPath != "" {
		policyCfg.PolicyPath = raw.Policy.PolicyPath
	}
	if raw.Policy.DecisionPath != "" {
		policyCfg.DecisionPath = raw.Policy.DecisionPath
	}
}
```

**Step 6: Run test to verify it passes**

Run: `go test ./cmd/veilwarden -run TestParseConfigWithOPAPolicy -v`

Expected: PASS

**Step 7: Commit**

```bash
git add cmd/veilwarden/config.go cmd/veilwarden/config_test.go
git commit -m "feat: extend config to support OPA policy settings"
```

---

## Task 4: Implement OPA Policy Engine

**Files:**
- Create: `cmd/veilwarden/opa_policy.go`

**Step 1: Write failing test for OPA engine initialization**

Create `cmd/veilwarden/opa_policy_test.go`:

```go
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
```

**Step 2: Run tests to verify they fail**

Run: `go test ./cmd/veilwarden -run TestOPAPolicy -v`

Expected: FAIL with "undefined: newOPAPolicyEngine"

**Step 3: Implement OPA policy engine**

Create `cmd/veilwarden/opa_policy.go`:

```go
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/v1/sdk"
)

// opaPolicyEngine implements PolicyEngine using Open Policy Agent.
type opaPolicyEngine struct {
	opa          *sdk.OPA
	decisionPath string
}

// newOPAPolicyEngine creates a new OPA-backed policy engine.
// It loads all .rego files from the specified policy path.
func newOPAPolicyEngine(ctx context.Context, cfg policyConfig) (*opaPolicyEngine, error) {
	if cfg.PolicyPath == "" {
		return nil, fmt.Errorf("policy_path is required for OPA engine")
	}

	// Load all .rego files from policy path
	policies, err := loadRegoFiles(cfg.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}

	if len(policies) == 0 {
		return nil, fmt.Errorf("no .rego files found in %s", cfg.PolicyPath)
	}

	// Create OPA SDK configuration
	config := []byte(fmt.Sprintf(`{
		"services": {},
		"bundles": {},
		"decision_logs": {
			"console": false
		}
	}`))

	// Initialize OPA SDK
	opa, err := sdk.New(ctx, sdk.Options{
		Config: bytes.NewReader(config),
		// Provide policies directly via in-memory bundle
		Ready: func(ctx context.Context) {
			// OPA is ready
		},
	})
	if err != nil {
		return nil, fmt.Errorf("initialize OPA SDK: %w", err)
	}

	// Load policies into OPA
	for path, content := range policies {
		if err := opa.InsertPolicy(ctx, path, []byte(content)); err != nil {
			opa.Stop(ctx)
			return nil, fmt.Errorf("insert policy %s: %w", path, err)
		}
	}

	decisionPath := cfg.DecisionPath
	if decisionPath == "" {
		decisionPath = "veilwarden/authz/allow"
	}

	return &opaPolicyEngine{
		opa:          opa,
		decisionPath: decisionPath,
	}, nil
}

// loadRegoFiles reads all .rego files from the specified directory.
// Returns a map of filename -> file content.
func loadRegoFiles(dir string) (map[string]string, error) {
	policies := make(map[string]string)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if filepath.Ext(entry.Name()) != ".rego" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		policies[entry.Name()] = string(content)
	}

	return policies, nil
}

// Decide implements PolicyEngine using OPA policy evaluation.
func (p *opaPolicyEngine) Decide(ctx context.Context, input PolicyInput) (PolicyDecision, error) {
	// Convert PolicyInput to map for OPA
	inputMap := map[string]interface{}{
		"method":        input.Method,
		"path":          input.Path,
		"query":         input.Query,
		"upstream_host": input.UpstreamHost,
		"agent_id":      input.AgentID,
		"user_id":       input.UserID,
		"user_email":    input.UserEmail,
		"user_org":      input.UserOrg,
		"secret_id":     input.SecretID,
		"request_id":    input.RequestID,
		"timestamp":     input.Timestamp.Format(time.RFC3339),
	}

	// Query OPA for decision
	result, err := p.opa.Decision(ctx, sdk.DecisionOptions{
		Path:  p.decisionPath,
		Input: inputMap,
	})
	if err != nil {
		return PolicyDecision{}, fmt.Errorf("OPA decision: %w", err)
	}

	// Extract boolean result
	allowed, ok := result.Result.(bool)
	if !ok {
		return PolicyDecision{}, fmt.Errorf("OPA decision returned non-boolean: %T", result.Result)
	}

	decision := PolicyDecision{
		Allowed: allowed,
		Metadata: map[string]string{
			"engine":      "opa",
			"decision_id": result.ID,
		},
	}

	if allowed {
		decision.Reason = "allowed by OPA policy"
	} else {
		decision.Reason = "denied by OPA policy"
	}

	return decision, nil
}

// Close shuts down the OPA instance.
func (p *opaPolicyEngine) Close() {
	if p.opa != nil {
		p.opa.Stop(context.Background())
	}
}
```

**Step 4: Add required import**

Add to imports in `cmd/veilwarden/opa_policy.go`:

```go
import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/open-policy-agent/opa/v1/sdk"
)
```

**Step 5: Run tests to verify they pass**

Run: `go test ./cmd/veilwarden -run TestOPAPolicy -v`

Expected: PASS (all 3 tests)

**Step 6: Commit**

```bash
git add cmd/veilwarden/opa_policy.go cmd/veilwarden/opa_policy_test.go
git commit -m "feat: implement OPA policy engine"
```

---

## Task 5: Update Policy Engine Factory

**Files:**
- Modify: `cmd/veilwarden/main.go:72-73`

**Step 1: Write test for policy engine selection**

Add to `cmd/veilwarden/main_test.go` (create if doesn't exist):

```go
func TestBuildPolicyEngineConfig(t *testing.T) {
	tests := []struct {
		name       string
		cfg        policyConfig
		expectType string
	}{
		{
			name: "disabled returns config engine",
			cfg: policyConfig{
				Enabled: false,
			},
			expectType: "*main.configPolicyEngine",
		},
		{
			name: "config engine enabled",
			cfg: policyConfig{
				Enabled:      true,
				Engine:       "config",
				DefaultAllow: true,
			},
			expectType: "*main.configPolicyEngine",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := buildPolicyEngine(context.Background(), tt.cfg)
			if engine == nil {
				t.Fatal("expected engine, got nil")
			}
			actualType := fmt.Sprintf("%T", engine)
			if actualType != tt.expectType {
				t.Errorf("expected type %s, got %s", tt.expectType, actualType)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/veilwarden -run TestBuildPolicyEngine -v`

Expected: FAIL with "undefined: buildPolicyEngine"

**Step 3: Create policy engine factory function**

Add to `cmd/veilwarden/main.go` after `buildSecretStore` function:

```go
func buildPolicyEngine(ctx context.Context, cfg policyConfig) PolicyEngine {
	// If policy disabled, return allow-all config engine
	if !cfg.Enabled {
		return newConfigPolicyEngine(policyConfig{
			Enabled:      false,
			DefaultAllow: true,
		})
	}

	// Select engine based on config
	switch cfg.Engine {
	case "opa":
		engine, err := newOPAPolicyEngine(ctx, cfg)
		if err != nil {
			slog.Error("Failed to initialize OPA policy engine",
				"error", err,
				"hint", "Verify policy_path exists and contains valid .rego files")
			os.Exit(1)
		}
		slog.Info("OPA policy engine initialized",
			"policy_path", cfg.PolicyPath,
			"decision_path", cfg.DecisionPath)
		return engine
	case "config", "":
		return newConfigPolicyEngine(cfg)
	default:
		slog.Error("Unknown policy engine",
			"engine", cfg.Engine,
			"hint", "Valid engines: 'config', 'opa'")
		os.Exit(1)
		return nil
	}
}
```

**Step 4: Replace direct policy engine creation in main**

Modify `cmd/veilwarden/main.go:72-73`:

```go
// Initialize policy engine
policyEngine := buildPolicyEngine(ctx, appCfg.policy)
```

**Step 5: Run test to verify it passes**

Run: `go test ./cmd/veilwarden -run TestBuildPolicyEngine -v`

Expected: PASS

**Step 6: Run all tests to ensure no regressions**

Run: `go test ./cmd/veilwarden -v`

Expected: All tests PASS

**Step 7: Commit**

```bash
git add cmd/veilwarden/main.go cmd/veilwarden/main_test.go
git commit -m "feat: add policy engine factory with OPA support"
```

---

## Task 6: Add Integration Test

**Files:**
- Create: `cmd/veilwarden/integration_opa_test.go`

**Step 1: Create integration test with real OPA policies**

Create `cmd/veilwarden/integration_opa_test.go`:

```go
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
	}, nil, engine, "alice", "alice@company.com", "engineering")

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
	}, nil, engine, "bob", "bob@company.com", "external")

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
```

**Step 2: Run integration tests**

Run: `go test ./cmd/veilwarden -run TestOPAIntegration -v`

Expected: PASS (both tests)

**Step 3: Commit**

```bash
git add cmd/veilwarden/integration_opa_test.go
git commit -m "test: add OPA integration tests"
```

---

## Task 7: Update Documentation

**Files:**
- Modify: `README.md`
- Create: `examples/opa-config.yaml`

**Step 1: Create example OPA configuration**

Create `examples/opa-config.yaml`:

```yaml
# Example veilwarden configuration with OPA policy engine

routes:
  - upstream_host: api.github.com
    upstream_scheme: https
    secret_id: GITHUB_TOKEN
    inject_header: Authorization
    header_value_template: "token {{secret}}"

  - upstream_host: api.stripe.com
    upstream_scheme: https
    secret_id: STRIPE_API_KEY
    inject_header: Authorization
    header_value_template: "Bearer {{secret}}"

# OPA Policy Configuration
policy:
  enabled: true
  engine: opa                          # Use OPA engine instead of config
  policy_path: policies/               # Directory containing .rego files
  decision_path: veilwarden/authz/allow # OPA query path (default)

# Note: secrets section omitted when using Doppler
```

**Step 2: Add OPA documentation section to README**

Add to `README.md` after existing policy section:

```markdown
## OPA Policy Integration

Veilwarden supports Open Policy Agent (OPA) for production-grade authorization policies.

### Enabling OPA

1. **Create policy files** in a directory (e.g., `policies/`):

```rego
package veilwarden.authz

import rego.v1

default allow := false

# Allow GET requests from engineering
allow if {
    input.method == "GET"
    input.user_org == "engineering"
}

# Allow CI agents to POST to GitHub
allow if {
    input.method == "POST"
    input.upstream_host == "api.github.com"
    input.agent_id == "ci-agent"
}
```

2. **Configure veilwarden.yaml**:

```yaml
policy:
  enabled: true
  engine: opa
  policy_path: policies/
  decision_path: veilwarden/authz/allow
```

3. **Start with user context**:

```bash
veilwarden --config veilwarden.yaml \
  --user-id alice \
  --user-email alice@company.com \
  --user-org engineering
```

### Policy Input Structure

Policies receive comprehensive request context:

```json
{
  "method": "POST",
  "path": "/repos/user/repo",
  "query": "page=1",
  "upstream_host": "api.github.com",
  "agent_id": "cli-tool",
  "user_id": "alice",
  "user_email": "alice@company.com",
  "user_org": "engineering",
  "request_id": "abc123",
  "timestamp": "2025-11-16T12:00:00Z"
}
```

### Decision Path

Policies must define a boolean decision at the configured path (default: `veilwarden/authz/allow`).

See `policies/example.rego` for complete examples.
```

**Step 3: Commit documentation**

```bash
git add README.md examples/opa-config.yaml
git commit -m "docs: add OPA integration documentation and examples"
```

---

## Task 8: Run Full Test Suite and Verification

**Files:**
- All test files

**Step 1: Run complete test suite**

Run: `go test ./cmd/veilwarden -v`

Expected: All tests PASS (including config, policy, OPA, server, and integration tests)

**Step 2: Verify no import cycles**

Run: `go build ./cmd/veilwarden`

Expected: Successful compilation with no errors

**Step 3: Test with example policy**

```bash
# Use the example policy from policies/allow_all.rego
go run ./cmd/veilwarden \
  --config examples/opa-config.yaml \
  --session-secret test123 \
  --user-org engineering
```

Expected: Server starts successfully with "OPA policy engine initialized" log

**Step 4: Manual verification (optional)**

If Doppler is configured, test a real request:

```bash
curl -v http://127.0.0.1:8088/test \
  -H "X-Session-Secret: test123" \
  -H "X-Upstream-Host: api.github.com" \
  -H "X-Agent-Id: test-agent"
```

Expected: 200 OK if policy allows, 403 POLICY_DENIED if denied

**Step 5: Final commit**

```bash
git add -A
git commit -m "feat: complete OPA integration with tests and docs"
```

---

## Task 9: Update Configuration Test Coverage

**Files:**
- Modify: `cmd/veilwarden/config_test.go`

**Step 1: Add test for invalid engine**

Add to `cmd/veilwarden/config_test.go`:

```go
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
```

**Step 2: Add test for backwards compatibility**

Add to `cmd/veilwarden/config_test.go`:

```go
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
```

**Step 3: Run config tests**

Run: `go test ./cmd/veilwarden -run TestParseConfig -v`

Expected: All config tests PASS

**Step 4: Commit**

```bash
git add cmd/veilwarden/config_test.go
git commit -m "test: add OPA config validation tests"
```

---

## Completion Checklist

After completing all tasks, verify:

- [ ] OPA v1 SDK dependency added to go.mod
- [ ] Example policy files created in `policies/` directory
- [ ] Configuration extended to support OPA settings
- [ ] `opaPolicyEngine` implements `PolicyEngine` interface
- [ ] Policy engine factory selects correct engine based on config
- [ ] Integration tests pass with real OPA policies
- [ ] Documentation updated with OPA examples
- [ ] All tests pass (`go test ./cmd/veilwarden -v`)
- [ ] Binary compiles successfully (`go build ./cmd/veilwarden`)
- [ ] Backwards compatibility maintained (config engine still works)
- [ ] Error messages are helpful when OPA fails to initialize

## Rollout Strategy

**Phase 1: Soft Launch**
- Keep `engine: config` as default
- Document OPA as opt-in feature
- Gather feedback on policy structure

**Phase 2: Production Hardening**
- Add policy validation on startup
- Support policy hot-reload
- Add policy decision audit logging

**Phase 3: Advanced Features**
- Bundle support for policy distribution
- Remote policy updates
- Policy testing framework
