# VeilWarden Security Fixes - Design Document

**Date**: 2025-11-19
**Status**: Approved
**Author**: VeilWarden Team

## Overview

Fix three critical security bugs in laptop mode (`veil exec`) that violate the "zero-knowledge agents" design goal:

1. **DOPPLER_TOKEN leak** - Master credential passed to child process
2. **Policy enforcement disabled** - Hardcoded allow-all despite config support
3. **Sandbox flag misleading** - Non-functional flag creates false sense of security

## Problem Statement

### Bug 1: DOPPLER_TOKEN Leak

**Current behavior:**
- `buildProxyEnv()` copies all parent environment variables to child except proxy vars
- DOPPLER_TOKEN is passed through to agent process
- Agent can call `os.getenv('DOPPLER_TOKEN')` and access ALL secrets via Doppler API
- Completely bypasses proxy and policy enforcement

**Impact:** Critical - Violates core security promise that agents cannot access raw credentials.

**Location:** `cmd/veil/exec.go:207-243` (buildProxyEnv function)

### Bug 2: Policy Enforcement Disabled

**Current behavior:**
- Line 123: `policyEngine := proxy.NewAllowAllPolicyEngine()` hardcoded
- Policy config is loaded but never used
- All requests allowed regardless of policy.engine, policy.opa_policy_path, etc.
- README promises OPA enforcement but it's non-functional

**Impact:** High - Agents have unrestricted API access, contradicts documentation.

**Location:** `cmd/veil/exec.go:122-123`

### Bug 3: Sandbox Flag Non-Functional

**Current behavior:**
- `--sandbox` flag declared and documented
- Flag value never referenced in code
- Users think they have filesystem isolation but don't
- Silently ignored, no warning or error

**Impact:** Medium - False sense of security for users running untrusted code.

**Location:** `cmd/veil/exec.go:41,50` (declaration only)

## Design Goals

1. Strip DOPPLER_TOKEN from child environment while preserving other env vars for user flexibility
2. Wire up existing OPA policy engine infrastructure to laptop mode
3. Make `--sandbox` flag fail fast with clear "not implemented" error
4. Maintain backward compatibility - existing commands continue working
5. No authentication required for local proxy (localhost = trusted)

## Success Criteria

- Child process cannot access DOPPLER_TOKEN via `os.getenv()`
- Policy rules from config.yaml are enforced for laptop mode requests
- `veil exec --sandbox` returns actionable error instead of false success
- All existing tests continue to pass
- E2E test validates DOPPLER_TOKEN is not visible to child

## Technical Design

### Fix 1: DOPPLER_TOKEN Stripping

**Approach:** Modify `buildProxyEnv()` to explicitly filter DOPPLER_TOKEN.

**Implementation:**

```go
func buildProxyEnv(parentEnv []string, proxyURL, caCertPath string) []string {
    env := make([]string, 0, len(parentEnv)+15)

    // Copy parent env, filtering out sensitive tokens and proxy vars
    for _, e := range parentEnv {
        key := strings.SplitN(e, "=", 2)[0]
        lower := strings.ToLower(key)

        // Strip DOPPLER_TOKEN (master credential that can access all secrets)
        if key == "DOPPLER_TOKEN" {
            continue
        }

        // Strip existing proxy vars (existing logic)
        if strings.HasPrefix(lower, "http_proxy") ||
           strings.HasPrefix(lower, "https_proxy") ||
           strings.Contains(lower, "_ca_") {
            continue
        }

        env = append(env, e)
    }

    // Add proxy configuration... (existing code)
    return env
}
```

**Rationale:**
- Parent process (veil) keeps DOPPLER_TOKEN for future Doppler integration
- Child process (agent) cannot access it
- Other secrets (OPENAI_API_KEY) remain for user flexibility
- Can revisit more aggressive stripping later if needed

### Fix 2: Policy Enforcement Integration

**Approach:** Replace hardcoded allow-all with policy engine factory based on config.

**Implementation:**

Add new function to `cmd/veil/exec.go`:

```go
func buildPolicyEngine(cfg *veilConfig) (proxy.PolicyEngine, error) {
    // If no policy configured, default to allow-all (backward compatibility)
    if cfg.Policy.Engine == "" || cfg.Policy.Engine == "disabled" {
        return proxy.NewAllowAllPolicyEngine(), nil
    }

    // If config-based policy
    if cfg.Policy.Engine == "config" {
        return proxy.NewConfigPolicyEngine(cfg.Policy.DefaultDecision == "allow"), nil
    }

    // If OPA policy
    if cfg.Policy.Engine == "opa" {
        // Import needed: "veilwarden/cmd/veilwarden/opa"
        return opa.NewOPAPolicyEngine(
            cfg.Policy.PolicyPath,
            cfg.Policy.DecisionPath,
            cfg.Policy.DefaultDecision,
        )
    }

    return nil, fmt.Errorf("unknown policy engine type: %s (valid options: disabled, config, opa)", cfg.Policy.Engine)
}
```

Replace line 122-123:

```go
// OLD:
// For MVP: Use allow-all policy (TODO: OPA integration)
policyEngine := proxy.NewAllowAllPolicyEngine()

// NEW:
policyEngine, err := buildPolicyEngine(cfg)
if err != nil {
    return fmt.Errorf("failed to initialize policy engine: %w", err)
}
```

**Backward Compatibility:**
- Empty or `disabled` engine → allow-all (existing behavior)
- Users must explicitly set `policy.engine: opa` to enforce restrictions
- Reuses all existing policy engine code from sidecar mode

**OPA Import Requirements:**
- Need to move OPA engine to shared package or import from cmd/veilwarden/opa
- May need to refactor OPA engine to internal/policy/ for sharing

### Fix 3: Sandbox Flag Error Handling

**Approach:** Check flag early in `runExec()` and return clear error.

**Implementation:**

Add at start of `runExec()` (after line 55):

```go
func runExec(cmd *cobra.Command, args []string) error {
    // Check for unimplemented features
    if execSandbox {
        return fmt.Errorf(
            "sandbox mode is not yet implemented\n\n" +
            "The --sandbox flag is currently non-functional and provides no isolation.\n" +
            "Track implementation progress at: https://github.com/yourusername/veilwarden/issues/XXX\n\n" +
            "To run without sandboxing, remove the --sandbox flag.",
        )
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // ... rest of existing code
}
```

**User Experience:**

```bash
$ veil exec --sandbox -- python agent.py
Error: sandbox mode is not yet implemented

The --sandbox flag is currently non-functional and provides no isolation.
Track implementation progress at: https://github.com/yourusername/veilwarden/issues/XXX

To run without sandboxing, remove the --sandbox flag.
```

**Alternative Considered:** Remove flag entirely. Rejected because keeping it signals intent and provides better UX than "unknown flag" error.

## Testing Strategy

### Unit Tests

**File:** `cmd/veil/exec_test.go` (new file)

**Test 1: DOPPLER_TOKEN Stripping**

```go
func TestBuildProxyEnv_StripsDopplerToken(t *testing.T) {
    parentEnv := []string{
        "DOPPLER_TOKEN=dp.st.dev.secret123",
        "OPENAI_API_KEY=sk-test",
        "PATH=/usr/bin",
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
    for _, e := range childEnv {
        if strings.HasPrefix(e, "OPENAI_API_KEY=") {
            hasOpenAI = true
        }
    }
    if !hasOpenAI {
        t.Fatal("OPENAI_API_KEY should remain in child environment")
    }
}
```

**Test 2: Policy Engine Initialization**

```go
func TestBuildPolicyEngine_RespectsConfig(t *testing.T) {
    tests := []struct {
        name       string
        config     *veilConfig
        wantAllowAll bool
        wantErr    bool
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
            _, isAllowAll := engine.(*proxy.AllowAllPolicyEngine)
            if tt.wantAllowAll && !isAllowAll {
                t.Fatal("expected AllowAllPolicyEngine")
            }
        })
    }
}
```

**Test 3: Sandbox Flag Error**

```go
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

### E2E Test

**File:** `test_veil_e2e.sh`

Add new test case:

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

## Implementation Plan

### Files to Modify

1. **`cmd/veil/exec.go`**:
   - Add sandbox flag error check (line ~56)
   - Modify `buildProxyEnv()` to strip DOPPLER_TOKEN (line ~213)
   - Add `buildPolicyEngine()` function (new)
   - Replace hardcoded allow-all with `buildPolicyEngine(cfg)` (line ~123)

2. **`cmd/veil/exec_test.go`** (new file):
   - Test DOPPLER_TOKEN stripping
   - Test policy engine initialization
   - Test sandbox flag error

3. **`test_veil_e2e.sh`**:
   - Add Test 4: DOPPLER_TOKEN stripping
   - Add Test 5: Sandbox flag error

4. **`internal/policy/`** (potential new package):
   - Move OPA engine from cmd/veilwarden/opa to shared location
   - Or: keep in cmd/veilwarden and import (creates dependency)

### Implementation Order

1. **Task 1:** Add sandbox flag error check (5 lines, immediate safety improvement)
2. **Task 2:** Strip DOPPLER_TOKEN from environment (3 lines, critical security fix)
3. **Task 3:** Move/share OPA engine code if needed (~50 lines refactor)
4. **Task 4:** Add `buildPolicyEngine()` and wire up (~40 lines)
5. **Task 5:** Add unit tests (~100 lines)
6. **Task 6:** Update E2E test (~15 lines)
7. **Task 7:** Update README with security notes (~20 lines)
8. **Task 8:** Create GitHub issue for sandbox implementation tracking

**Estimated Total:** ~230 lines new/modified code

### Risks & Mitigations

**Risk 1:** Breaking existing users who don't have policy configured
- **Mitigation:** Default to allow-all when `policy.engine` is empty or "disabled"
- **Test:** Verify backward compatibility with empty config

**Risk 2:** OPA initialization failures in laptop mode
- **Mitigation:** Return clear errors with config validation hints
- **Test:** Add test for invalid OPA config paths

**Risk 3:** Import cycle if OPA code stays in cmd/veilwarden
- **Mitigation:** Consider moving to internal/policy/ or internal/opa/
- **Alternative:** Accept the cmd/veil → cmd/veilwarden import for OPA only

**Risk 4:** Users expect full environment sanitization
- **Mitigation:** Document clearly that only DOPPLER_TOKEN is stripped currently
- **Future:** Can add more aggressive stripping in later release

## Documentation Updates

### README.md Changes

Add security note to laptop mode section:

```markdown
### Security Notes for Laptop Mode

**Current Limitations:**

1. **Environment Variable Handling**: Currently only `DOPPLER_TOKEN` is stripped from the
   child process environment. Other secrets (OPENAI_API_KEY, etc.) remain visible to the
   agent process. This is by design for flexibility, but means agents could potentially
   access these values directly. Future versions may add more aggressive environment
   sanitization.

2. **Policy Enforcement**: Policies are enforced when configured, but default to allow-all
   for backward compatibility. Always set `policy.engine: opa` in production.

3. **Sandbox Mode**: The `--sandbox` flag is not yet implemented. Attempting to use it
   will return an error. Track progress at [issue #XXX].
```

## Future Enhancements

1. **Full Doppler Integration**: Proxy fetches secrets from Doppler, no secrets in environment
2. **Aggressive Environment Stripping**: Strip all *_API_KEY, *_TOKEN patterns by default
3. **Sandbox Implementation**: Integrate with anthropic/sandbox-runtime or gVisor
4. **TLS for Local Proxy**: Add option for mTLS authentication even on localhost
5. **Audit Logging**: Log all secret access attempts for security monitoring

## Appendix: Threat Model

**In Scope:**
- Agent cannot access DOPPLER_TOKEN to fetch all secrets
- Agent actions are subject to policy enforcement (when configured)
- Users are not misled about security features

**Out of Scope (Current Design):**
- Agent can still see individual API keys in environment (user responsibility)
- No authentication required for local proxy (localhost = trusted)
- No TLS for local proxy traffic
- No filesystem isolation (sandbox not implemented)

**Assumption:** User running `veil exec` is trusted and responsible for the secrets they
export to their shell environment. The proxy prevents *privilege escalation* (DOPPLER_TOKEN
→ all secrets) and enforces policy, but does not provide complete isolation.
