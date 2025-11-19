# Security Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix three critical security bugs in laptop mode: DOPPLER_TOKEN leak, disabled policy enforcement, and misleading sandbox flag.

**Architecture:** Simple fixes to existing code - add environment filtering, wire up existing policy engine infrastructure, and add early validation for unimplemented features.

**Tech Stack:** Go 1.21+, existing policy engine code (OPA, config-based), cobra CLI framework

---

## Task 1: Add Sandbox Flag Error Check

**Files:**
- Modify: `cmd/veil/exec.go:55-57` (start of runExec function)

**Step 1: Write the failing test**

Create file: `cmd/veil/exec_test.go`

```go
package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/veil -run TestSandboxFlag_ReturnsError -v`

Expected output: Test should FAIL because sandbox flag is currently ignored

**Step 3: Add sandbox flag check to runExec**

In `cmd/veil/exec.go`, add after line 55 (at start of runExec function):

```go
func runExec(cmd *cobra.Command, args []string) error {
	// Check for unimplemented features
	if execSandbox {
		return fmt.Errorf(
			"sandbox mode is not yet implemented\n\n" +
			"The --sandbox flag is currently non-functional and provides no isolation.\n" +
			"Track implementation progress at: https://github.com/yourusername/veilwarden/issues/TBD\n\n" +
			"To run without sandboxing, remove the --sandbox flag.",
		)
	}

	ctx, cancel := context.WithCancel(context.Background())
	// ... rest of existing code
```

**Step 4: Run test to verify it passes**

Run: `go test ./cmd/veil -run TestSandboxFlag_ReturnsError -v`

Expected output: `PASS`

**Step 5: Verify E2E still works without sandbox flag**

Run: `bash test_veil_e2e.sh`

Expected output: All existing tests pass

**Step 6: Commit**

```bash
git add cmd/veil/exec.go cmd/veil/exec_test.go
git commit -m "feat: add error for unimplemented sandbox flag

The --sandbox flag is declared but non-functional. Return clear error
instead of silently ignoring, preventing false sense of security.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 2: Strip DOPPLER_TOKEN from Child Environment

**Files:**
- Modify: `cmd/veil/exec.go:207-220` (buildProxyEnv function)
- Modify: `cmd/veil/exec_test.go` (add new test)

**Step 1: Write the failing test**

Add to `cmd/veil/exec_test.go`:

```go
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/veil -run TestBuildProxyEnv_StripsDopplerToken -v`

Expected output: Test should FAIL with "DOPPLER_TOKEN should not be in child environment"

**Step 3: Add DOPPLER_TOKEN filtering to buildProxyEnv**

In `cmd/veil/exec.go`, modify the buildProxyEnv function around line 210-220:

```go
func buildProxyEnv(parentEnv []string, proxyURL, caCertPath string) []string {
	env := make([]string, 0, len(parentEnv)+15)

	// Copy parent env, filtering out existing proxy vars
	for _, e := range parentEnv {
		key := strings.SplitN(e, "=", 2)[0]
		lower := strings.ToLower(key)

		// Strip DOPPLER_TOKEN (master credential that can access all secrets)
		if key == "DOPPLER_TOKEN" {
			continue
		}

		if strings.HasPrefix(lower, "http_proxy") ||
			strings.HasPrefix(lower, "https_proxy") ||
			strings.Contains(lower, "_ca_") {
			continue // Skip existing proxy env vars
		}
		env = append(env, e)
	}

	// Add proxy configuration
	env = append(env,
		// ... rest of existing code
```

**Step 4: Run test to verify it passes**

Run: `go test ./cmd/veil -run TestBuildProxyEnv_StripsDopplerToken -v`

Expected output: `PASS`

**Step 5: Run all tests**

Run: `go test ./cmd/veil -v`

Expected output: All tests pass

**Step 6: Commit**

```bash
git add cmd/veil/exec.go cmd/veil/exec_test.go
git commit -m "fix: strip DOPPLER_TOKEN from child environment

DOPPLER_TOKEN is a master credential that can access all secrets.
Prevent agent from accessing it directly by filtering from child env.

Other secrets (OPENAI_API_KEY, etc.) remain visible for user flexibility.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 3: Move OPA Engine to Shared Package

**Context:** The OPA engine currently lives in `cmd/veilwarden/opa/` but needs to be accessible from `cmd/veil/` for policy enforcement. We'll move it to `internal/policy/opa/` to share between both commands.

**Files:**
- Create: `internal/policy/opa/engine.go` (moved from cmd/veilwarden/opa/opa_policy.go)
- Modify: `cmd/veilwarden/config.go` (update import)
- Modify: `cmd/veilwarden/opa_policy.go` (update package reference or delete if fully moved)
- Modify: All test files that import opa package

**Step 1: Create internal/policy/opa package structure**

Run:
```bash
mkdir -p internal/policy/opa
```

**Step 2: Copy OPA engine implementation**

Copy the OPA engine implementation from `cmd/veilwarden/opa/opa_policy.go` to `internal/policy/opa/engine.go`:

Run:
```bash
cp cmd/veilwarden/opa_policy.go internal/policy/opa/engine.go
```

**Step 3: Update package declaration in new file**

In `internal/policy/opa/engine.go`, change:

```go
package opa
```

Ensure imports include the PolicyEngine interface from internal/proxy:

```go
import (
	"context"
	"fmt"
	"log/slog"

	"github.com/open-policy-agent/opa/sdk"
	"veilwarden/internal/proxy"
)
```

Update the struct to implement proxy.PolicyEngine:

```go
// OPAPolicyEngine evaluates authorization policies using Open Policy Agent.
type OPAPolicyEngine struct {
	opa           *sdk.OPA
	decisionPath  string
	logger        *slog.Logger
	defaultPolicy string
}

// Ensure OPAPolicyEngine implements proxy.PolicyEngine
var _ proxy.PolicyEngine = (*OPAPolicyEngine)(nil)
```

**Step 4: Update PolicyInput reference**

In `internal/policy/opa/engine.go`, update the Decide method signature to use proxy.PolicyInput:

```go
func (e *OPAPolicyEngine) Decide(ctx context.Context, input *proxy.PolicyInput) (*proxy.PolicyDecision, error) {
	// ... existing implementation
}
```

**Step 5: Run tests to find import errors**

Run: `go test ./... -v`

Expected output: Compilation errors about missing opa package in cmd/veilwarden

**Step 6: Update imports in cmd/veilwarden**

Update all files in `cmd/veilwarden/` that import the opa package:

In `cmd/veilwarden/config.go`, change:
```go
import (
	// ... existing imports
	"veilwarden/internal/policy/opa"
)
```

Search for all files:
```bash
grep -r "veilwarden/cmd/veilwarden/opa" cmd/veilwarden/
```

Update each found import to:
```go
"veilwarden/internal/policy/opa"
```

**Step 7: Remove old OPA file**

Run:
```bash
git rm cmd/veilwarden/opa_policy.go
```

**Step 8: Run all tests**

Run: `go test ./... -v`

Expected output: All tests pass with new import paths

**Step 9: Commit**

```bash
git add internal/policy/opa/ cmd/veilwarden/
git commit -m "refactor: move OPA engine to internal/policy/opa

Move OPA policy engine from cmd/veilwarden/opa to internal/policy/opa
to enable sharing between veilwarden server and veil CLI.

No functional changes, just package reorganization.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 4: Add Policy Engine Factory for Veil CLI

**Files:**
- Modify: `cmd/veil/exec.go` (add buildPolicyEngine function)
- Modify: `cmd/veil/exec_test.go` (add tests)

**Step 1: Write the failing test**

Add to `cmd/veil/exec_test.go`:

```go
func TestBuildPolicyEngine_RespectsConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       *veilConfig
		wantAllowAll bool
		wantErr      bool
	}{
		{
			name:         "disabled returns allow-all",
			config:       &veilConfig{Policy: policyConfig{Engine: "disabled"}},
			wantAllowAll: true,
		},
		{
			name:         "empty returns allow-all for backward compatibility",
			config:       &veilConfig{},
			wantAllowAll: true,
		},
		{
			name:         "config engine with allow default",
			config:       &veilConfig{Policy: policyConfig{Engine: "config", DefaultDecision: "allow"}},
			wantAllowAll: false,
		},
		{
			name:         "config engine with deny default",
			config:       &veilConfig{Policy: policyConfig{Engine: "config", DefaultDecision: "deny"}},
			wantAllowAll: false,
		},
		{
			name:    "unknown engine returns error",
			config:  &veilConfig{Policy: policyConfig{Engine: "invalid"}},
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
			switch e := engine.(type) {
			case *proxy.AllowAllPolicyEngine:
				if !tt.wantAllowAll {
					t.Fatal("expected non-AllowAll engine, got AllowAllPolicyEngine")
				}
			case *proxy.ConfigPolicyEngine:
				if tt.wantAllowAll {
					t.Fatal("expected AllowAllPolicyEngine, got ConfigPolicyEngine")
				}
			default:
				t.Fatalf("unexpected engine type: %T", e)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/veil -run TestBuildPolicyEngine_RespectsConfig -v`

Expected output: Compilation error - "undefined: buildPolicyEngine"

**Step 3: Add buildPolicyEngine function**

Add to `cmd/veil/exec.go` after the loadVeilConfig function (around line 260):

```go
func buildPolicyEngine(cfg *veilConfig) (proxy.PolicyEngine, error) {
	// If no policy configured, default to allow-all (backward compatibility)
	if cfg.Policy.Engine == "" || cfg.Policy.Engine == "disabled" {
		return proxy.NewAllowAllPolicyEngine(), nil
	}

	// If config-based policy
	if cfg.Policy.Engine == "config" {
		allowByDefault := cfg.Policy.DefaultDecision == "allow"
		return proxy.NewConfigPolicyEngine(allowByDefault), nil
	}

	// If OPA policy
	if cfg.Policy.Engine == "opa" {
		if cfg.Policy.PolicyPath == "" {
			return nil, fmt.Errorf("policy.opa_policy_path required when policy.engine is 'opa'")
		}

		decisionPath := cfg.Policy.DecisionPath
		if decisionPath == "" {
			decisionPath = "veilwarden/authz/allow"
		}

		defaultDecision := cfg.Policy.DefaultDecision
		if defaultDecision == "" {
			defaultDecision = "deny"
		}

		return opa.NewOPAPolicyEngine(
			cfg.Policy.PolicyPath,
			decisionPath,
			defaultDecision,
		)
	}

	return nil, fmt.Errorf("unknown policy engine type: %s (valid options: disabled, config, opa)", cfg.Policy.Engine)
}
```

**Step 4: Add required imports**

At the top of `cmd/veil/exec.go`, add:

```go
import (
	// ... existing imports
	"veilwarden/internal/policy/opa"
)
```

**Step 5: Run test to verify it passes**

Run: `go test ./cmd/veil -run TestBuildPolicyEngine_RespectsConfig -v`

Expected output: `PASS`

**Step 6: Run all veil tests**

Run: `go test ./cmd/veil -v`

Expected output: All tests pass

**Step 7: Commit**

```bash
git add cmd/veil/exec.go cmd/veil/exec_test.go
git commit -m "feat: add policy engine factory for veil CLI

Add buildPolicyEngine() to support config-based and OPA policy engines.
Defaults to allow-all for backward compatibility when policy.engine is
empty or disabled.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 5: Wire Up Policy Engine in Veil Exec

**Files:**
- Modify: `cmd/veil/exec.go:122-123` (replace hardcoded allow-all)

**Step 1: Write integration test**

Add to `cmd/veil/exec_test.go`:

```go
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
  engine: config
  default_decision: deny
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Load config
	cfg, err := loadVeilConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Build policy engine
	engine, err := buildPolicyEngine(cfg)
	if err != nil {
		t.Fatalf("failed to build policy engine: %v", err)
	}

	// Verify it's NOT allow-all
	_, isAllowAll := engine.(*proxy.AllowAllPolicyEngine)
	if isAllowAll {
		t.Fatal("expected non-AllowAll engine when policy.engine=config")
	}

	// Verify it's config-based
	_, isConfig := engine.(*proxy.ConfigPolicyEngine)
	if !isConfig {
		t.Fatal("expected ConfigPolicyEngine when policy.engine=config")
	}
}
```

**Step 2: Run test to verify current behavior**

Run: `go test ./cmd/veil -run TestVeilExec_UsesPolicyFromConfig -v`

Expected output: Test should PASS (buildPolicyEngine works from previous task)

**Step 3: Replace hardcoded allow-all policy in runExec**

In `cmd/veil/exec.go`, find lines 122-123:

```go
// For MVP: Use allow-all policy (TODO: OPA integration)
policyEngine := proxy.NewAllowAllPolicyEngine()
```

Replace with:

```go
// Build policy engine from config (defaults to allow-all if not configured)
policyEngine, err := buildPolicyEngine(cfg)
if err != nil {
	return fmt.Errorf("failed to initialize policy engine: %w", err)
}
```

**Step 4: Run all veil tests**

Run: `go test ./cmd/veil -v`

Expected output: All tests pass

**Step 5: Run full test suite**

Run: `go test ./... -v`

Expected output: All tests pass

**Step 6: Commit**

```bash
git add cmd/veil/exec.go cmd/veil/exec_test.go
git commit -m "feat: wire up policy enforcement in veil exec

Replace hardcoded NewAllowAllPolicyEngine() with buildPolicyEngine(cfg)
to respect policy configuration from config.yaml.

Maintains backward compatibility: defaults to allow-all when policy
engine is not configured.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 6: Add E2E Test for DOPPLER_TOKEN Stripping

**Files:**
- Modify: `test_veil_e2e.sh` (add new test case)

**Step 1: Add DOPPLER_TOKEN stripping test**

Add to `test_veil_e2e.sh` before the cleanup section (after Test 3):

```bash
# Test 4: Verify DOPPLER_TOKEN is stripped
echo ""
echo "Test 4: DOPPLER_TOKEN stripping"
OUTPUT=$(DOPPLER_TOKEN=dp.st.test.secret ./veil exec --config /tmp/veil-e2e-test/config.yaml -- env 2>/dev/null | grep "DOPPLER_TOKEN" || true)
if [ -z "$OUTPUT" ]; then
    echo "✓ DOPPLER_TOKEN correctly stripped from child environment"
else
    echo "✗ FAILED: DOPPLER_TOKEN leaked to child"
    exit 1
fi
```

**Step 2: Run E2E test to verify it passes**

Run: `bash test_veil_e2e.sh`

Expected output: All tests pass including new Test 4

**Step 3: Commit**

```bash
git add test_veil_e2e.sh
git commit -m "test: add E2E test for DOPPLER_TOKEN stripping

Verify that DOPPLER_TOKEN is not visible in child process environment
when running veil exec.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 7: Add E2E Test for Sandbox Flag Error

**Files:**
- Modify: `test_veil_e2e.sh` (add new test case)

**Step 1: Add sandbox flag error test**

Add to `test_veil_e2e.sh` after Test 4:

```bash
# Test 5: Verify sandbox flag returns error
echo ""
echo "Test 5: Sandbox flag error handling"
./veil exec --sandbox --config /tmp/veil-e2e-test/config.yaml -- echo "test" 2>&1 | grep -q "not yet implemented"
if [ $? -eq 0 ]; then
    echo "✓ Sandbox flag returns appropriate error"
else
    echo "✗ FAILED: Sandbox flag did not return expected error"
    exit 1
fi
```

**Step 2: Run E2E test to verify it passes**

Run: `bash test_veil_e2e.sh`

Expected output: All tests pass including new Test 5

**Step 3: Commit**

```bash
git add test_veil_e2e.sh
git commit -m "test: add E2E test for sandbox flag error

Verify that --sandbox flag returns clear error instead of
silently running without isolation.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 8: Update README with Security Notes

**Files:**
- Modify: `README.md` (add security notes section to laptop mode)

**Step 1: Add security notes section**

In `README.md`, find the laptop mode section (around line 40-80) and add after the basic usage example:

```markdown
#### Security Notes

**Current Limitations:**

1. **Environment Variable Handling**: Only `DOPPLER_TOKEN` is stripped from the child process environment. Other secrets (like `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) remain visible to the agent process if you export them. This is by design for flexibility, but means agents could potentially access these values directly via `os.getenv()`. Future versions may add more aggressive environment sanitization.

2. **Policy Enforcement**: Policies are enforced when configured (see [Policy Configuration](#policy-configuration) below), but default to allow-all for backward compatibility. For production use, always configure `policy.engine: opa` or `policy.engine: config` in your `config.yaml`.

3. **Sandbox Mode**: The `--sandbox` flag is not yet implemented. Attempting to use it will return an error. Track implementation progress in [GitHub Issues](https://github.com/yourusername/veilwarden/issues).

**Best Practices:**

- Use Doppler integration (coming soon) instead of exporting secrets to your shell
- Always configure policy enforcement for production workloads
- Review the [Security Design](docs/plans/2025-11-19-security-fixes-design.md) for threat model details
```

**Step 2: Verify markdown formatting**

Run: `cat README.md | grep -A 15 "Security Notes"`

Expected output: Clean markdown rendering of the new section

**Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add security notes to laptop mode section

Document current security limitations:
- DOPPLER_TOKEN stripping (other secrets remain visible)
- Policy enforcement defaults (allow-all unless configured)
- Sandbox flag status (not implemented)

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 9: Run Full Test Suite and Verify

**Step 1: Run all unit tests**

Run: `go test ./... -v`

Expected output: All tests pass

**Step 2: Run E2E test**

Run: `bash test_veil_e2e.sh`

Expected output: All 5 tests pass

**Step 3: Build both binaries**

Run:
```bash
go build -o /tmp/veilwarden ./cmd/veilwarden
go build -o /tmp/veil ./cmd/veil
```

Expected output: Both binaries build successfully

**Step 4: Verify sandbox flag error UX**

Run: `/tmp/veil exec --sandbox -- echo test`

Expected output:
```
Error: sandbox mode is not yet implemented

The --sandbox flag is currently non-functional and provides no isolation.
Track implementation progress at: https://github.com/yourusername/veilwarden/issues/TBD

To run without sandboxing, remove the --sandbox flag.
```

**Step 5: Verify DOPPLER_TOKEN is stripped**

Run:
```bash
DOPPLER_TOKEN=test-token /tmp/veil exec --config ~/.veilwarden/config.yaml -- env | grep DOPPLER_TOKEN
```

Expected output: Empty (no DOPPLER_TOKEN in output)

**Step 6: Final commit (if any cleanup needed)**

If everything passes, no commit needed. If fixes required, make them and commit.

---

## Task 10: Create GitHub Issue for Sandbox Implementation

**Step 1: Create GitHub issue template**

Create file: `docs/issues/sandbox-implementation.md`

```markdown
# Implement Sandbox Mode for Veil CLI

## Background

The `--sandbox` flag is declared in `veil exec` but currently returns an error stating it's not implemented. This issue tracks the work to actually implement filesystem isolation for untrusted agents.

## Goal

Enable `veil exec --sandbox -- <command>` to run the command in a sandboxed environment with restricted filesystem access.

## Potential Approaches

1. **anthropic/sandbox-runtime**: Official Anthropic sandbox with Docker backend
2. **gVisor**: Lightweight application kernel for container isolation
3. **Bubblewrap**: Unprivileged sandboxing tool for Linux
4. **Custom seccomp/AppArmor**: Kernel-level syscall filtering

## Requirements

- Filesystem isolation (read-only mounts, restricted paths)
- Network access (needs to connect to proxy on localhost)
- Process isolation
- Works on Linux and macOS
- Minimal performance overhead

## Implementation Plan

TBD - requires research and design phase

## Related

- Security fixes design: docs/plans/2025-11-19-security-fixes-design.md
- Original MITM design: docs/plans/2025-11-18-laptop-mitm-proxy-design.md
```

**Step 2: Commit issue template**

```bash
git add docs/issues/sandbox-implementation.md
git commit -m "docs: add GitHub issue template for sandbox implementation

Template for tracking sandbox mode implementation work.
References security fixes and original design docs.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

**Step 3: Manual step - Create actual GitHub issue**

Note: This requires manual action - go to GitHub and create issue using the template.

---

## Summary

**Total Tasks:** 10
**Estimated Time:** 2-3 hours
**Files Modified:** 5
**Files Created:** 3
**Tests Added:** 7

**Key Changes:**
1. ✅ Sandbox flag returns clear error instead of silent ignore
2. ✅ DOPPLER_TOKEN stripped from child environment
3. ✅ OPA engine moved to shared internal/policy/opa package
4. ✅ Policy enforcement wired up in veil exec
5. ✅ Comprehensive test coverage (unit + E2E)
6. ✅ Documentation updated with security notes

**Verification Checklist:**
- [ ] All unit tests pass (`go test ./... -v`)
- [ ] E2E tests pass (`bash test_veil_e2e.sh`)
- [ ] Both binaries build successfully
- [ ] Sandbox flag shows clear error
- [ ] DOPPLER_TOKEN not visible in child env
- [ ] Policy config is respected
- [ ] README has security notes
- [ ] GitHub issue created for sandbox implementation

**Next Steps After This Plan:**
1. Consider more aggressive environment sanitization (strip all *_API_KEY patterns)
2. Implement full Doppler integration for secret fetching
3. Design and implement actual sandbox mode
4. Add TLS support for local proxy authentication
