# VeilWarden Security

This document describes security features, mitigations, and known limitations of VeilWarden.

## Security Features

### 1. Request Body Size Limiting (DoS Protection)

**Protection**: VeilWarden limits the request body size read for policy evaluation to **1 MB** to prevent denial-of-service attacks via memory exhaustion.

**Implementation**:
- `MaxPolicyBodySize = 1MB` constant in `internal/proxy/martian.go` and `cmd/veilwarden/martian_modifiers.go`
- Uses `io.LimitReader` to cap body reads before passing to OPA policy engine
- Bodies larger than 1MB are truncated for policy evaluation only
- Warning logged when truncation occurs
- Request body is restored for forwarding to upstream (truncated version)

**Rationale**: Malicious agents or compromised services could send multi-gigabyte request bodies to exhaust proxy memory. The 1MB limit is sufficient for most API requests (including large JSON payloads) while preventing memory-based DoS.

**Configuration**: Currently not configurable. The 1MB default is chosen to support:
- OpenAI API requests (typically < 100KB)
- Anthropic API requests (typically < 500KB)
- Large batch operations (up to 1MB)

**Location**:
- `internal/proxy/martian.go:20-25` (constant definition)
- `internal/proxy/martian.go:127-152` (enforcement in policyModifier)
- `cmd/veilwarden/martian_modifiers.go:14-19` (constant definition)
- `cmd/veilwarden/martian_modifiers.go:44-69` (enforcement in policyModifier)

### 2. HTTP Header Injection Prevention

**Protection**: VeilWarden validates all secret values and header templates before injection to prevent HTTP header injection attacks.

**Implementation**:
- `isValidHeaderValue()` function validates strings per RFC 7230
- Allows: visible ASCII (0x21-0x7E), space (0x20), tab (0x09)
- Rejects: control characters including CR (0x0D), LF (0x0A), null bytes
- Validation applied to:
  1. Secret values fetched from secret store
  2. Final header value after template substitution

**Rationale**: If a secret value contains newline characters (`\r\n`), an attacker could inject additional HTTP headers:
```
Authorization: Bearer sk-token\r\nX-Injected: malicious
```

This would result in:
```
Authorization: Bearer sk-token
X-Injected: malicious
```

While secrets are unlikely to contain such characters, defense-in-depth requires validation to prevent:
- Compromised secret stores returning malicious values
- Configuration errors in header templates
- Future integrations with untrusted secret sources

**Errors**: Requests are rejected with HTTP 500 if:
- Secret value contains invalid characters: `"secret <ID> contains invalid characters for HTTP header"`
- Header value after substitution contains invalid characters: `"header value for <NAME> contains invalid characters"`

**Location**:
- `internal/proxy/martian.go:27-41` (validation function)
- `internal/proxy/martian.go:248-266` (enforcement in secretInjectorModifier)
- `cmd/veilwarden/martian_modifiers.go:21-35` (validation function)
- `cmd/veilwarden/martian_modifiers.go:149-167` (enforcement in secretInjectorModifier)
- `cmd/veilwarden/server.go:336-357` (enforcement in HTTP handler)

### 3. DOPPLER_TOKEN Stripping (Laptop Mode)

**Protection**: The `DOPPLER_TOKEN` environment variable is stripped from child processes in laptop mode to prevent agents from bypassing the proxy.

**Rationale**: If `DOPPLER_TOKEN` is visible to the agent via `os.getenv()`, the agent can call the Doppler API directly to fetch all secrets, completely bypassing VeilWarden's policy enforcement and audit logging.

**Implementation**: See [Security Fixes Design](plans/2025-11-19-security-fixes-design.md) for full details.

**Location**: `cmd/veil/exec.go` (buildProxyEnv function)

### 4. Sandbox Isolation (Optional)

**Protection**: VeilWarden can run agent processes in isolated sandboxes to prevent unauthorized filesystem access.

**Implementation**:
- Pluggable sandbox backend interface
- Anthropic sandbox as first implementation (external CLI)
- Explicit mount declarations for controlled access
- All network traffic still goes through veil MITM proxy

**Rationale**: Even with network-level controls, compromised agents could:
- Read sensitive files (~/.ssh/id_rsa, ~/.aws/credentials)
- Write malicious files to system directories
- Persist malware between runs

Sandboxing provides defense-in-depth by isolating the filesystem.

**Configuration**:
```yaml
sandbox:
  enabled: true
  backend: anthropic
  mounts:
    - host: ./project
      container: /workspace
      readonly: false
```

**What sandbox protects:**
- Reading sensitive files unless explicitly mounted
- Writing to system directories
- Filesystem persistence (only mounts persist)

**What sandbox does NOT protect:**
- Network access (still controlled by veil proxy + OPA)
- Resource exhaustion (depends on backend)
- Kernel exploits (depends on backend isolation mechanism)

**Location**:
- Design: `docs/plans/2025-11-21-sandbox-integration-design.md`
- Implementation: `cmd/veil/sandbox/`
- Tests: `test/sandbox_integration_test.sh`

## Security Limitations

### 1. Environment Variable Visibility (Laptop Mode)

**Current Behavior**: Only `DOPPLER_TOKEN` is stripped from the child process environment. Other secrets (like `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) remain visible if exported to the parent shell.

**Risk**: Agents can access these values directly via `os.getenv()` without going through the proxy.

**Mitigation**: Use Doppler integration instead of exporting secrets to your shell. When using Doppler:
- Secrets are fetched directly by VeilWarden
- Only `DOPPLER_TOKEN` needs to be in the environment
- Agent never sees the actual API keys

**Future Work**: Consider implementing more aggressive environment sanitization or a `--strict` mode that removes all secrets from child environment.

### 2. Session Secret (Laptop Mode - Server Mode Only)

**Current Behavior**: The veilwarden server uses a single `X-Session-Secret` for local authentication in server mode.

**Risk**: If this secret is leaked (e.g., via process listing, logs, or compromised agent), an attacker on the local machine could bypass authentication.

**Mitigation**:
- Laptop mode (veil CLI) does not use session secrets - the local proxy trusts localhost
- Server mode should only be used on trusted machines
- Session secret should be passed via secure channel (environment variable is acceptable for local dev)
- Never log the session secret value

**Note**: This limitation only applies to the veilwarden server mode, not the recommended `veil exec` laptop mode.

### 3. Policy Enforcement Default

**Current Behavior**: Policies default to allow-all for backward compatibility if not explicitly configured.

**Risk**: Users may believe they have policy enforcement when they don't.

**Mitigation**: Always configure `policy.engine: opa` or `policy.engine: config` in your configuration file for production use.

**Example** (`~/.veilwarden/config.yaml`):
```yaml
policy:
  engine: opa
  bundle_path: ~/.veilwarden/policies
  decision_path: veilwarden/authz/allow
```


## Security Best Practices

### For Laptop Mode (veil CLI)

1. **Use Doppler Integration**: Instead of exporting secrets to your shell, use Doppler:
   ```bash
   export DOPPLER_TOKEN=dp.st.dev.xxxxx
   veil exec -- python my_agent.py
   ```

2. **Configure Policy Enforcement**: Always use OPA policies in production:
   ```yaml
   policy:
     engine: opa
     bundle_path: ~/.veilwarden/policies
     decision_path: veilwarden/authz/allow
   ```

3. **Review Policies**: Ensure your OPA policies are deny-by-default:
   ```rego
   package veilwarden.authz
   import rego.v1

   default allow := false

   # Explicitly allow only what you need
   allow if {
     input.method == "POST"
     input.path == "/v1/chat/completions"
     # ... more constraints
   }
   ```

### For Server Mode (veilwarden)

1. **Use Strong Session Secrets**: Generate cryptographically random session secrets:
   ```bash
   export VEILWARDEN_SESSION_SECRET="$(openssl rand -hex 32)"
   ```

2. **Rotate Secrets Regularly**: Rotate session secrets and API keys on a regular schedule.

3. **Monitor Logs**: Review logs for denied requests and suspicious patterns.

4. **Use Kubernetes Identity**: For production deployments, use Kubernetes Service Account tokens instead of session secrets.

## Reporting Security Issues

If you discover a security vulnerability in VeilWarden, please report it via [GitHub Security Advisories](https://github.com/yourusername/veilwarden/security/advisories/new).

Please do **not** open a public issue for security vulnerabilities.

## Changelog

### 2025-11-20: DoS and Header Injection Fixes

- Added 1MB request body size limit for policy evaluation
- Added HTTP header validation to prevent injection attacks
- Both fixes applied to:
  - `internal/proxy` (MITM proxy for laptop mode)
  - `cmd/veilwarden` (server mode)
- Added comprehensive tests for security features

### 2025-11-19: Security Fixes

- Stripped DOPPLER_TOKEN from child environment (laptop mode)
- Wired up OPA policy engine to laptop mode
- Made `--sandbox` flag fail fast with clear error
- See [Security Fixes Design](plans/2025-11-19-security-fixes-design.md) for full details
