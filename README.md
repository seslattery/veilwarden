![veilwarden](https://github.com/user-attachments/assets/a943fe76-1e34-48b7-80f1-89b48cedd593)

# Veilwarden

> Secure guardrails for AI agents: credential injection + sandbox isolation.

Veilwarden lets you safely run AI agents with API access while preventing them from:
- **Seeing your credentials** - secrets injected at the network layer, never in code
- **Accessing sensitive files** - sandbox blocks `~/.ssh`, `~/.aws`, credentials, etc.
- **Bypassing the proxy** - network isolation forces all traffic through Veilwarden
- **Making unauthorized requests** - OPA policies control what endpoints agents can call

```
┌─────────────────────────────────────────────────────────────────┐
│                         SANDBOX                                 │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐     │
│  │  AI Agent   │ ──── │  Veilwarden │ ──── │  APIs       │     │
│  │  (no keys)  │      │  (injects   │      │  (OpenAI,   │     │
│  │             │      │   secrets)  │      │   etc.)     │     │
│  └─────────────┘      └─────────────┘      └─────────────┘     │
│        │                                                        │
│        ├── ✗ Can't read ~/.ssh, ~/.aws, ~/.config              │
│        ├── ✗ Can't bypass proxy (network isolated)             │
│        └── ✗ Can't see DOPPLER_TOKEN or raw credentials        │
└─────────────────────────────────────────────────────────────────┘
```

**Why?**
- **Zero-trust agents** - Secrets can't leak from code that never has them
- **Defense in depth** - Even if an agent is compromised, it can't exfiltrate credentials or SSH keys
- **Centralized control** - Manage credentials and policies across all agents in one place
- **Drop-in security** - No code changes required; works with any HTTP client

> **Status:** Experimental - expect breaking changes

---

## Quick Start

```bash
# Install
go install github.com/yourusername/veilwarden/cmd/veil@latest

# Initialize config
veil init

# Set your API keys
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...

# Run any command through the proxy
veil exec -- python my_agent.py
veil exec -- curl https://api.openai.com/v1/models

# Run with sandbox enabled (recommended for untrusted agents)
veil exec --sandbox -- python untrusted_agent.py
```

Your agent makes normal HTTP requests. Veilwarden intercepts them and adds the appropriate `Authorization` header based on the destination host.

With `--sandbox`, the agent also runs in an isolated environment that blocks access to sensitive files and forces all network traffic through the proxy.

---

## Configuration

Config lives at `~/.veilwarden/config.yaml`. Run `veil init` to create it.

### Routes (Required)

Map hosts to secrets:

```yaml
routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

  - host: api.anthropic.com
    secret_id: ANTHROPIC_API_KEY
    header_name: x-api-key
    header_value_template: "{{secret}}"
```

### Secrets

**Option A: Environment variables** (default)

Secrets are read from env vars matching `secret_id`:

```bash
export OPENAI_API_KEY=sk-...
veil exec -- python agent.py
```

**Option B: Doppler**

For centralized secret management:

```yaml
doppler:
  project: my-project
  config: dev
```

```bash
export DOPPLER_TOKEN=dp.st.xxx
veil exec -- python agent.py
```

If Doppler is configured but `DOPPLER_TOKEN` isn't set, falls back to env vars.

### Policy (Optional)

Control which requests are allowed using [OPA](https://www.openpolicyagent.org/):

```yaml
policy:
  engine: opa
  policy_path: ~/.veilwarden/policies
  decision_path: veilwarden/authz/allow
```

See `policies/example.rego` for policy examples.

---

## Sandbox Isolation

The sandbox is a critical security layer that prevents AI agents from accessing sensitive files or bypassing the proxy. When enabled, agents run in a restricted environment with:

**Network Isolation:**
- All network traffic forced through the Veilwarden proxy
- Direct TCP connections blocked (prevents proxy bypass)
- DNS resolution controlled (prevents data exfiltration via DNS)
- Raw socket creation blocked

**Filesystem Isolation:**
- Sensitive directories blocked by default (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.doppler`, etc.)
- Write access limited to specified directories only
- Symlink/hardlink attacks prevented
- Path traversal attacks blocked

```yaml
sandbox:
  enabled: true
  backend: auto                    # auto | seatbelt | srt
  working_dir: ./my-project
  allowed_write_paths:
    - ./my-project                 # Agent can write here
    - /tmp/agent-workspace         # And here
  denied_read_paths:
    - ~/.ssh                       # Blocked (also blocked by default)
    - ~/.aws
    - ~/.config/gcloud
    - ~/secrets                    # Add your own sensitive paths
```

**Backends:**
| Backend | Platform | Implementation |
|---------|----------|----------------|
| `auto` | macOS/Linux | Native sandbox (recommended) |
| `seatbelt` | macOS | Uses `sandbox-exec` |
| `srt` | Any | Anthropic's [sandbox-runtime](https://www.npmjs.com/package/@anthropic-ai/sandbox-runtime) |

**Default blocked paths:** `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.doppler`, `~/.gnupg`, `~/.kube`, `~/.docker`, `/etc/shadow`, `/etc/sudoers`

See [Sandbox Quickstart](docs/sandbox-quickstart.md) for detailed setup.

---

## CLI Reference

```bash
veil init                        # Create default config
veil exec -- <command>           # Run command through proxy
veil exec --sandbox -- <cmd>     # Force sandbox on
veil exec --no-sandbox -- <cmd>  # Force sandbox off
veil exec --verbose -- <cmd>     # Show proxy logs
```

---

## Security Model

Veilwarden provides **defense in depth** with multiple security layers:

| Layer | Protection | Threat Mitigated |
|-------|------------|------------------|
| **Credential Injection** | Secrets added at network layer | Agent code never sees API keys |
| **Network Isolation** | All traffic forced through proxy | Can't bypass proxy or exfiltrate data |
| **Filesystem Sandbox** | Sensitive paths blocked | Can't read SSH keys, cloud credentials |
| **OPA Policies** | Fine-grained request control | Limit which APIs/endpoints are accessible |
| **Env Stripping** | `DOPPLER_TOKEN` removed | Can't access secret store directly |

**What this means in practice:**
- An AI agent can call OpenAI/Anthropic APIs without ever seeing the API keys
- Even if the agent is jailbroken or malicious, it cannot:
  - Read your SSH keys or cloud credentials
  - Make direct network connections to exfiltrate data
  - Access the Doppler token to fetch other secrets
  - Call unauthorized API endpoints (with OPA enabled)

**Limitations:**
- Other exported env vars are visible to child processes (use Doppler for sensitive values)
- Sandbox is experimental (macOS seatbelt and srt backends available; Linux bubblewrap coming soon)
- OPA policies default to allow-all for backward compatibility

See [SECURITY.md](docs/SECURITY.md) for the full threat model.

---

## Development

```bash
# Setup
just setup

# Test
just test          # All tests
just test-veil     # CLI tests only
just test-e2e      # E2E tests (requires DOPPLER_TOKEN + srt)

# Build
just build         # Output: bin/veil
```

Prerequisites: Go 1.21+, [just](https://github.com/casey/just) (optional)
