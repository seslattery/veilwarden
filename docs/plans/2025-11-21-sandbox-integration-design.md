# VeilWarden Sandbox Integration - Design Document

**Date**: 2025-11-21
**Status**: Design Phase
**Author**: VeilWarden Team

## Overview

Add pluggable sandbox support to `veil exec` to provide comprehensive process and filesystem isolation for AI agents. The first implementation will use Anthropic's sandbox, with the architecture designed to support multiple sandbox backends in the future.

## Goals

1. **Process Isolation**: Run agent processes in isolated sandboxes to prevent unauthorized filesystem access
2. **Filesystem Control**: Allow explicit mount declarations for controlled persistence while isolating sensitive files
3. **Network Security**: Maintain zero-trust network model - all traffic goes through veil's MITM proxy
4. **Pluggable Architecture**: Design for multiple sandbox backends (Anthropic first, gVisor/Firecracker later)
5. **Simple Interface**: Coarse-grained API - sandbox handles isolation complexity internally

## Non-Goals

- Fine-grained syscall filtering (delegated to sandbox implementation)
- Custom resource limits beyond what sandbox backend provides
- Container orchestration (single-process sandbox only)
- Windows support (Linux/macOS only initially)

## Use Cases

### Use Case 1: Prevent Credential Theft
**Scenario**: AI agent with prompt injection vulnerability attempts to read `~/.ssh/id_rsa` or `~/.aws/credentials`

**Without sandbox**: Agent can read any file the user can read

**With sandbox**: Agent runs in isolated filesystem, cannot access `~/.ssh/` or `~/.aws/` unless explicitly mounted

### Use Case 2: Controlled Data Persistence
**Scenario**: Agent needs to persist learned data between runs, but shouldn't access other files

**Solution**: Mount `~/.cache/agent-data` into sandbox at `/data`:
```yaml
sandbox:
  mounts:
    - host: ~/.cache/agent-data
      container: /data
      readonly: false
```

Agent can read/write `/data` but nothing else persists.

### Use Case 3: Read-Only System Libraries
**Scenario**: Python agent needs standard library, but shouldn't modify system files

**Solution**: Mount Python libraries read-only:
```yaml
sandbox:
  mounts:
    - host: /usr/local/lib/python3.11
      container: /usr/local/lib/python3.11
      readonly: true
```

## Architecture

### High-Level Flow

```
veil exec --sandbox -- python agent.py
  ↓
1. veil reads ~/.veilwarden/config.yaml (sandbox + mounts config)
2. veil starts MITM proxy on random port
3. veil generates ephemeral CA certificate
4. veil prepares sandbox environment:
   - HTTP_PROXY=http://localhost:<port>
   - HTTPS_PROXY=http://localhost:<port>
   - SSL_CERT_FILE=/path/to/ca.crt
   - All user env vars (minus DOPPLER_TOKEN)
5. veil invokes sandbox backend (anthropic CLI):
   - Passes mounts from config
   - Passes prepared environment
   - Passes command to run
6. Sandbox starts, agent runs inside isolation
7. Agent makes API calls → HTTP_PROXY → veil MITM → policy check → secret injection → upstream
8. veil waits for sandbox process to exit
9. Cleanup: stop proxy, delete temp CA cert
```

### Component Diagram

```
┌─────────────────────────────────────────────────────────┐
│                     veil exec                           │
│                                                         │
│  ┌──────────────┐      ┌─────────────────┐            │
│  │ MITM Proxy   │◄─────┤ Sandbox Manager │            │
│  │ (existing)   │      │ (new)           │            │
│  └──────────────┘      └────────┬────────┘            │
│         ▲                       │                      │
│         │                       ▼                      │
│         │              ┌──────────────────┐            │
│         │              │ Sandbox Backend  │            │
│         │              │ Interface        │            │
│         │              └────────┬─────────┘            │
│         │                       │                      │
│         │         ┌─────────────┴──────────┐           │
│         │         │                        │           │
│         │    ┌────▼───────┐       ┌───────▼──────┐    │
│         │    │ Anthropic  │       │ Future:      │    │
│         │    │ Backend    │       │ gVisor, etc. │    │
│         │    └────┬───────┘       └──────────────┘    │
└─────────┼─────────┼──────────────────────────────────┘
          │         │
          │         ▼
          │   ┌──────────────────────────────────┐
          │   │  anthropic-sandbox CLI           │
          │   │  (external process)              │
          │   │                                  │
          │   │  ┌────────────────────────────┐ │
          │   │  │  Sandboxed Agent Process   │ │
          │   │  │  - python agent.py         │ │
          │   │  │  - Isolated filesystem     │ │
          │   │  │  - Mounts: /workspace, etc │ │
          │   │  └───────────┬────────────────┘ │
          │   └──────────────┼───────────────────┘
          │                  │
          └──────────────────┘
              HTTP requests via proxy
```

## Configuration Schema

### Config File (`~/.veilwarden/config.yaml`)

```yaml
# Existing veil config
routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

policy:
  engine: opa
  bundle_path: ~/.veilwarden/policies
  decision_path: veilwarden/authz/allow

# New sandbox section
sandbox:
  # Enable/disable sandboxing
  enabled: true

  # Backend selection (only 'anthropic' for now)
  backend: anthropic

  # Filesystem mounts
  mounts:
    # Project directory (read-write)
    - host: ./project              # Relative to current dir
      container: /workspace
      readonly: false

    # Persistent data (read-write)
    - host: ~/.cache/agent-data    # Absolute path
      container: /data
      readonly: false

    # System libraries (read-only)
    - host: /usr/local/lib/python3.11
      container: /usr/local/lib/python3.11
      readonly: true

  # Working directory inside sandbox (optional)
  working_dir: /workspace

  # Optional: resource limits (if backend supports)
  resources:
    memory_mb: 2048
    cpu_cores: 2
```

### CLI Flags

```bash
# Enable sandbox (overrides config)
veil exec --sandbox -- python agent.py

# Disable even if config has it enabled
veil exec --no-sandbox -- python agent.py

# Default behavior respects config.yaml
veil exec -- python agent.py

# One-off mount (in addition to config mounts)
veil exec --sandbox --mount ./data:/data -- python agent.py
```

## Implementation

### File Structure

```
cmd/veil/
  exec.go              # Modified to wire up sandbox
  sandbox/
    sandbox.go         # Interface definition + factory
    anthropic.go       # Anthropic implementation
    config.go          # Config types
    config_test.go     # Config validation tests
    anthropic_test.go  # Anthropic backend tests
```

### Interface Definition

```go
// cmd/veil/sandbox/sandbox.go

package sandbox

import (
    "context"
    "io"
)

// Backend defines the interface for sandbox implementations.
type Backend interface {
    // Start launches the sandboxed process
    // Returns a running process handle and error
    Start(ctx context.Context, config *Config) (*Process, error)
}

// Config contains all settings needed to start a sandboxed process.
type Config struct {
    Command     []string          // e.g., ["python", "agent.py"]
    Env         []string          // e.g., ["HTTP_PROXY=...", "PATH=..."]
    Mounts      []Mount           // Filesystem mounts
    WorkingDir  string            // Working directory inside sandbox
}

// Mount represents a filesystem mount from host to container.
type Mount struct {
    HostPath      string
    ContainerPath string
    ReadOnly      bool
}

// Process represents a running sandboxed process.
type Process struct {
    PID    int
    Stdin  io.WriteCloser
    Stdout io.Reader
    Stderr io.Reader

    // Wait blocks until the process exits and returns the exit error
    Wait() error
}

// NewBackend creates a sandbox backend by name.
func NewBackend(backendType string) (Backend, error) {
    switch backendType {
    case "anthropic":
        return NewAnthropicBackend()
    default:
        return nil, fmt.Errorf("unknown sandbox backend: %s (available: anthropic)", backendType)
    }
}
```

### Anthropic Backend Implementation

```go
// cmd/veil/sandbox/anthropic.go

package sandbox

import (
    "context"
    "fmt"
    "os/exec"
)

type AnthropicBackend struct {
    cliPath string  // Path to anthropic-sandbox binary
}

func NewAnthropicBackend() (*AnthropicBackend, error) {
    // Check if anthropic-sandbox CLI exists
    cliPath, err := exec.LookPath("anthropic-sandbox")
    if err != nil {
        return nil, fmt.Errorf(
            "anthropic-sandbox CLI not found in PATH.\n" +
            "Install from: https://github.com/anthropics/sandbox\n" +
            "Or disable sandbox in config: sandbox.enabled: false")
    }

    return &AnthropicBackend{cliPath: cliPath}, nil
}

func (a *AnthropicBackend) Start(ctx context.Context, cfg *Config) (*Process, error) {
    args := a.buildArgs(cfg)

    cmd := exec.CommandContext(ctx, a.cliPath, args...)

    // Setup stdio pipes
    stdin, err := cmd.StdinPipe()
    if err != nil {
        return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
    }

    stdout, err := cmd.StdoutPipe()
    if err != nil {
        return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
    }

    stderr, err := cmd.StderrPipe()
    if err != nil {
        return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
    }

    // Start the sandbox process
    if err := cmd.Start(); err != nil {
        return nil, fmt.Errorf("failed to start sandbox: %w", err)
    }

    return &Process{
        PID:    cmd.Process.Pid,
        Stdin:  stdin,
        Stdout: stdout,
        Stderr: stderr,
        cmd:    cmd,
    }, nil
}

func (a *AnthropicBackend) buildArgs(cfg *Config) []string {
    args := []string{"run"}

    // Add mounts
    for _, m := range cfg.Mounts {
        // Expand ~ paths
        hostPath := expandPath(m.HostPath)

        flag := fmt.Sprintf("--mount=%s:%s", hostPath, m.ContainerPath)
        if m.ReadOnly {
            flag += ":ro"
        }
        args = append(args, flag)
    }

    // Add environment variables
    for _, e := range cfg.Env {
        args = append(args, "--env", e)
    }

    // Working directory
    if cfg.WorkingDir != "" {
        args = append(args, "--workdir", cfg.WorkingDir)
    }

    // Command separator and actual command
    args = append(args, "--")
    args = append(args, cfg.Command...)

    return args
}

// Process implementation
type Process struct {
    PID    int
    Stdin  io.WriteCloser
    Stdout io.Reader
    Stderr io.Reader
    cmd    *exec.Cmd
}

func (p *Process) Wait() error {
    err := p.cmd.Wait()
    p.Stdin.Close()
    return err
}
```

### Integration with exec.go

```go
// cmd/veil/exec.go

func runExec(cmd *cobra.Command, args []string) error {
    ctx := context.Background()

    // Load config
    cfg, err := loadConfig()
    if err != nil {
        return err
    }

    // Determine if sandbox should be used
    useSandbox := shouldUseSandbox(cfg, cmd)

    // Build sandbox backend if enabled
    var sandboxBackend sandbox.Backend
    if useSandbox {
        backend, err := sandbox.NewBackend(cfg.Sandbox.Backend)
        if err != nil {
            return fmt.Errorf("failed to create sandbox: %w", err)
        }
        sandboxBackend = backend
    }

    // Start MITM proxy (existing code)
    proxy, proxyURL, caCertPath, err := startMITMProxy(ctx, cfg)
    if err != nil {
        return err
    }
    defer proxy.Shutdown()

    // Build environment with proxy settings
    env := buildProxyEnv(os.Environ(), proxyURL, caCertPath)

    if sandboxBackend != nil {
        return runSandboxed(ctx, sandboxBackend, cfg, args, env)
    } else {
        return runDirect(args, env)
    }
}

func shouldUseSandbox(cfg *config.Config, cmd *cobra.Command) bool {
    // Check --sandbox flag
    if cmd.Flags().Changed("sandbox") {
        sandbox, _ := cmd.Flags().GetBool("sandbox")
        return sandbox
    }

    // Check --no-sandbox flag
    if cmd.Flags().Changed("no-sandbox") {
        noSandbox, _ := cmd.Flags().GetBool("no-sandbox")
        return !noSandbox
    }

    // Default to config
    return cfg.Sandbox != nil && cfg.Sandbox.Enabled
}

func runSandboxed(ctx context.Context, backend sandbox.Backend, cfg *config.Config, args, env []string) error {
    // Validate mounts
    if err := sandbox.ValidateMounts(cfg.Sandbox.Mounts); err != nil {
        return fmt.Errorf("invalid mount configuration: %w", err)
    }

    // Build sandbox config
    sandboxCfg := &sandbox.Config{
        Command:    args,
        Env:        env,
        Mounts:     cfg.Sandbox.Mounts,
        WorkingDir: cfg.Sandbox.WorkingDir,
    }

    // Start sandboxed process
    proc, err := backend.Start(ctx, sandboxCfg)
    if err != nil {
        return fmt.Errorf("sandbox start failed: %w", err)
    }

    // Pipe stdout/stderr to parent
    go io.Copy(os.Stdout, proc.Stdout)
    go io.Copy(os.Stderr, proc.Stderr)

    // Handle signals for graceful shutdown
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

    go func() {
        <-sigChan
        // Cancel context to kill sandbox process
        cancel()
    }()

    // Wait for completion
    return proc.Wait()
}

func runDirect(args, env []string) error {
    // Existing implementation - run command directly
    cmd := exec.Command(args[0], args[1:]...)
    cmd.Env = env
    cmd.Stdin = os.Stdin
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    return cmd.Run()
}
```

## Error Handling

### Sandbox Binary Not Found

```go
func NewAnthropicBackend() (*AnthropicBackend, error) {
    cliPath, err := exec.LookPath("anthropic-sandbox")
    if err != nil {
        return nil, fmt.Errorf(
            "anthropic-sandbox CLI not found in PATH.\n" +
            "\n" +
            "To install:\n" +
            "  1. Visit: https://github.com/anthropics/sandbox\n" +
            "  2. Follow installation instructions\n" +
            "  3. Verify: anthropic-sandbox --version\n" +
            "\n" +
            "Alternatively, disable sandboxing:\n" +
            "  - Use flag: veil exec --no-sandbox\n" +
            "  - Or in config: sandbox.enabled: false")
    }
    return &AnthropicBackend{cliPath: cliPath}, nil
}
```

### Mount Path Validation

```go
func ValidateMounts(mounts []Mount) error {
    for i, m := range mounts {
        // Expand ~/ paths
        hostPath, err := expandPath(m.HostPath)
        if err != nil {
            return fmt.Errorf("mount[%d]: invalid host path %s: %w", i, m.HostPath, err)
        }

        // Check host path exists
        if _, err := os.Stat(hostPath); os.IsNotExist(err) {
            return fmt.Errorf("mount[%d]: host path does not exist: %s", i, hostPath)
        }

        // Validate container path is absolute
        if !filepath.IsAbs(m.ContainerPath) {
            return fmt.Errorf("mount[%d]: container path must be absolute: %s", i, m.ContainerPath)
        }

        // Warn if mounting sensitive directories
        if isSensitivePath(hostPath) {
            fmt.Fprintf(os.Stderr, "WARNING: Mounting sensitive directory: %s\n", hostPath)
        }
    }
    return nil
}

func isSensitivePath(path string) bool {
    sensitive := []string{
        filepath.Join(os.Getenv("HOME"), ".ssh"),
        filepath.Join(os.Getenv("HOME"), ".aws"),
        filepath.Join(os.Getenv("HOME"), ".config/gcloud"),
        "/etc/passwd",
        "/etc/shadow",
    }

    for _, s := range sensitive {
        if strings.HasPrefix(path, s) {
            return true
        }
    }
    return false
}
```

### Proxy Connection Failures

```go
func runSandboxed(...) error {
    // ... start sandbox ...

    // Check if proxy is reachable from sandbox
    // This is a best-effort check before starting the actual command
    if err := verifyProxyConnectivity(ctx, proxyURL); err != nil {
        return fmt.Errorf(
            "sandbox cannot reach veil proxy at %s: %w\n" +
            "\n" +
            "This may indicate network isolation issues.\n" +
            "Verify the sandbox backend allows localhost connections.",
            proxyURL, err)
    }

    // ... continue ...
}
```

### Graceful Shutdown

```go
func runSandboxed(ctx context.Context, ...) error {
    // Create cancellable context
    ctx, cancel := context.WithCancel(ctx)
    defer cancel()

    // Start sandbox with cancellable context
    proc, err := backend.Start(ctx, sandboxCfg)
    if err != nil {
        return err
    }

    // Handle signals
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

    go func() {
        sig := <-sigChan
        fmt.Fprintf(os.Stderr, "\nReceived %s, stopping sandbox...\n", sig)
        cancel()  // Kills sandbox process via context
    }()

    // Wait for process to exit
    err = proc.Wait()

    // Cleanup
    cleanup(caCertPath)

    return err
}
```

## Testing Strategy

### Unit Tests

```go
// sandbox/config_test.go
func TestValidateMounts(t *testing.T) {
    tests := []struct{
        name    string
        mount   Mount
        wantErr bool
        errMsg  string
    }{
        {
            name:    "valid absolute paths",
            mount:   Mount{HostPath: "/tmp/data", ContainerPath: "/data", ReadOnly: false},
            wantErr: false,
        },
        {
            name:    "valid relative host path",
            mount:   Mount{HostPath: "./project", ContainerPath: "/workspace", ReadOnly: false},
            wantErr: false,
        },
        {
            name:    "invalid relative container path",
            mount:   Mount{HostPath: "/tmp", ContainerPath: "relative", ReadOnly: false},
            wantErr: true,
            errMsg:  "container path must be absolute",
        },
        {
            name:    "nonexistent host path",
            mount:   Mount{HostPath: "/does/not/exist", ContainerPath: "/workspace", ReadOnly: false},
            wantErr: true,
            errMsg:  "host path does not exist",
        },
        {
            name:    "tilde expansion",
            mount:   Mount{HostPath: "~/project", ContainerPath: "/workspace", ReadOnly: false},
            wantErr: false, // Should expand ~/
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidateMounts([]Mount{tt.mount})
            if tt.wantErr {
                assert.Error(t, err)
                if tt.errMsg != "" {
                    assert.Contains(t, err.Error(), tt.errMsg)
                }
            } else {
                assert.NoError(t, err)
            }
        })
    }
}

// sandbox/anthropic_test.go
func TestAnthropicBackend_BuildArgs(t *testing.T) {
    backend := &AnthropicBackend{cliPath: "anthropic-sandbox"}
    cfg := &Config{
        Command: []string{"python", "test.py"},
        Env: []string{
            "HTTP_PROXY=http://localhost:8080",
            "PATH=/usr/bin",
        },
        Mounts: []Mount{
            {HostPath: "/tmp/data", ContainerPath: "/data", ReadOnly: true},
            {HostPath: "/tmp/project", ContainerPath: "/workspace", ReadOnly: false},
        },
        WorkingDir: "/workspace",
    }

    args := backend.buildArgs(cfg)

    // Verify mounts
    assert.Contains(t, args, "--mount=/tmp/data:/data:ro")
    assert.Contains(t, args, "--mount=/tmp/project:/workspace")

    // Verify environment
    assert.Contains(t, args, "--env")
    assert.Contains(t, args, "HTTP_PROXY=http://localhost:8080")

    // Verify working directory
    assert.Contains(t, args, "--workdir")
    assert.Contains(t, args, "/workspace")

    // Verify command separator
    assert.Contains(t, args, "--")

    // Verify command comes after separator
    idx := indexOf(args, "--")
    assert.Greater(t, idx, -1)
    assert.Equal(t, []string{"python", "test.py"}, args[idx+1:])
}
```

### Integration Tests (requires anthropic-sandbox)

```bash
#!/bin/bash
# test/sandbox_integration_test.sh

set -e

echo "=== Sandbox Integration Test ==="

# Check if anthropic-sandbox is installed
if ! command -v anthropic-sandbox &> /dev/null; then
    echo "SKIP: anthropic-sandbox not installed"
    exit 0
fi

# Setup test environment
export OPENAI_API_KEY=sk-test-key-12345
TEST_DIR=$(mktemp -d)
cd "$TEST_DIR"

# Create test agent
cat > agent.py <<'EOF'
import os
import sys
import requests

# Try to read sensitive file (should fail)
try:
    with open(os.path.expanduser("~/.ssh/id_rsa"), "r") as f:
        print("ERROR: Could read SSH key!")
        sys.exit(1)
except FileNotFoundError:
    print("✓ Cannot access ~/.ssh/id_rsa (expected)")

# Try to make API call through proxy
try:
    resp = requests.get("https://api.openai.com/v1/models")
    print(f"✓ API call through proxy: {resp.status_code}")
except Exception as e:
    print(f"ERROR: API call failed: {e}")
    sys.exit(1)

# Try to write to mounted workspace
try:
    with open("/workspace/test.txt", "w") as f:
        f.write("test")
    print("✓ Can write to /workspace")
except Exception as e:
    print(f"ERROR: Cannot write to workspace: {e}")
    sys.exit(1)

print("✓ All checks passed")
EOF

# Create veil config
cat > config.yaml <<EOF
sandbox:
  enabled: true
  backend: anthropic
  mounts:
    - host: .
      container: /workspace
      readonly: false

routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"
EOF

# Run test
echo "Running agent in sandbox..."
veil exec --config config.yaml -- python /workspace/agent.py

# Verify persistence
if [ -f test.txt ]; then
    echo "✓ File persisted from sandbox"
else
    echo "ERROR: File not persisted"
    exit 1
fi

# Cleanup
cd -
rm -rf "$TEST_DIR"

echo "=== Sandbox Integration Test PASSED ==="
```

### E2E Test Scenarios

```go
// cmd/veil/sandbox_e2e_test.go
// +build e2e

func TestSandbox_E2E_BasicExecution(t *testing.T) {
    // Test: Agent runs in sandbox, makes API call through proxy
    // Verify: Request goes through veil, secret is injected
}

func TestSandbox_E2E_MountPersistence(t *testing.T) {
    // Test: Agent writes to mounted directory
    // Verify: File persists after sandbox exits
}

func TestSandbox_E2E_ReadonlyMount(t *testing.T) {
    // Test: Agent tries to write to readonly mount
    // Verify: Write fails with permission error
}

func TestSandbox_E2E_NetworkIsolation(t *testing.T) {
    // Test: Agent tries to access network without proxy
    // Verify: Direct network access is blocked
}

func TestSandbox_E2E_SecretIsolation(t *testing.T) {
    // Test: Agent tries to read DOPPLER_TOKEN from environment
    // Verify: DOPPLER_TOKEN is not visible
}

func TestSandbox_E2E_GracefulShutdown(t *testing.T) {
    // Test: Send SIGINT to veil while sandbox is running
    // Verify: Both sandbox and proxy cleanly terminate
}
```

### Manual Testing Checklist

Before release, manually verify:

- [ ] `veil exec --sandbox` without sandbox config → error: "sandbox.enabled is false or not configured"
- [ ] Invalid mount path → error: "host path does not exist: /invalid/path"
- [ ] `anthropic-sandbox` not installed → helpful error with installation link
- [ ] `--no-sandbox` flag disables sandbox even when config enables it
- [ ] Multiple mounts work correctly (can access all mounted paths)
- [ ] Readonly mounts prevent writes (permission denied errors)
- [ ] Sensitive directory warning shown when mounting ~/.ssh or ~/.aws
- [ ] SIGINT cleanly stops sandbox and proxy
- [ ] HTTP_PROXY env vars correctly set inside sandbox
- [ ] CA certificate accessible inside sandbox

## Security Considerations

### Threat Model

**What sandbox protects against**:
- Agent reading sensitive files (SSH keys, cloud credentials, browser cookies)
- Agent writing malware or modifying system files
- Agent persisting between runs (unless explicitly mounted)
- Agent accessing network without policy enforcement

**What sandbox does NOT protect against**:
- Network-based attacks (covered by veil's proxy + OPA policies)
- Malicious API responses from upstream
- Resource exhaustion (depends on sandbox backend's resource limits)
- Kernel exploits (depends on sandbox backend's isolation mechanism)

### Defense in Depth

Sandbox is one layer in VeilWarden's security model:

1. **Filesystem Isolation** (sandbox): Prevents unauthorized file access
2. **Network Control** (veil proxy): All traffic goes through MITM proxy
3. **Policy Enforcement** (OPA): Controls which APIs/paths are allowed
4. **Secret Injection** (veil): Agents never see raw credentials
5. **Audit Logging** (veil): Complete record of all API calls

### Escape Scenarios

If an attacker escapes the sandbox:
- Still cannot access raw API credentials (veil strips DOPPLER_TOKEN)
- Still subject to OPA policy enforcement (veil denies unauthorized requests)
- Audit logs capture all network activity

### Sensitive Mount Warning

When users mount sensitive directories, show clear warning:

```
WARNING: Mounting sensitive directory: /home/user/.ssh
This gives the agent access to SSH private keys.
Only proceed if you trust this agent completely.
```

## Migration Path

### Phase 1: Foundation (MVP)
- [ ] Implement sandbox interface
- [ ] Implement Anthropic backend
- [ ] Add config schema
- [ ] Basic integration with exec.go
- [ ] Unit tests

### Phase 2: Hardening
- [ ] Mount validation
- [ ] Error handling
- [ ] Sensitive path warnings
- [ ] Integration tests

### Phase 3: Polish
- [ ] E2E tests
- [ ] Documentation
- [ ] Example configs
- [ ] User guide

### Phase 4: Future Backends (Post-MVP)
- [ ] gVisor backend
- [ ] Firecracker backend
- [ ] Docker/Podman backend

## Open Questions

1. **Anthropic sandbox API**: What's the actual CLI interface? This design assumes:
   ```bash
   anthropic-sandbox run --mount=<host>:<container>[:ro] --env KEY=val -- command
   ```
   Need to verify against actual implementation.

2. **Network namespace**: How does Anthropic's sandbox handle network? Does it:
   - A) Allow full network access (we rely on HTTP_PROXY)
   - B) Block all network except localhost
   - C) Provide network namespace configuration

3. **Resource limits**: Does Anthropic sandbox support resource limits? If yes:
   - Should veil expose these in config?
   - Or let users configure via backend-specific settings?

4. **Temporary directory**: Should veil automatically mount a temp directory?
   ```yaml
   mounts:
     - host: /tmp/veil-sandbox-XXXXX
       container: /tmp
   ```

5. **CA certificate mount**: Current design sets `SSL_CERT_FILE` env var. Does the sandbox need an explicit mount for the CA cert file?

## Success Criteria

### Must Have (MVP)
- [ ] Agent runs inside Anthropic sandbox
- [ ] All HTTP traffic goes through veil proxy
- [ ] Mounts work correctly (readonly and read-write)
- [ ] Sensitive files inaccessible unless explicitly mounted
- [ ] DOPPLER_TOKEN stripped from sandbox environment
- [ ] Clear error when anthropic-sandbox not installed
- [ ] Unit tests pass
- [ ] Integration tests pass (if anthropic-sandbox available)

### Nice to Have (Post-MVP)
- [ ] Resource limits configuration
- [ ] Multiple sandbox backends
- [ ] Automatic temp directory mounting
- [ ] Better diagnostics for sandbox failures
- [ ] Performance benchmarks

### Success Metrics
- Sandbox adds < 100ms overhead to startup
- No false positives in mount validation
- Zero sandbox escapes in testing
- 100% test coverage for sandbox package

## References

- [Anthropic Sandbox](https://github.com/anthropics/sandbox) - Assumed, verify actual repository
- [VeilWarden Security Fixes](./2025-11-19-security-fixes-design.md) - DOPPLER_TOKEN stripping
- [gVisor](https://gvisor.dev/) - Alternative sandbox backend
- [Firecracker](https://firecracker-microvm.github.io/) - Alternative sandbox backend
