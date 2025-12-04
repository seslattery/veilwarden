# Veilwarden

**Your AI agents shouldn't know your API keys.**

Veilwarden is a local proxy that injects secrets into outbound HTTP requests. Your code never sees credentials - they're added transparently at the network layer.

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│  Your Agent │ ──── │  Veilwarden │ ──── │  OpenAI API │
│  (no keys)  │      │  (injects)  │      │             │
└─────────────┘      └─────────────┘      └─────────────┘
```

**Why?**
- Secrets can't leak from agent code that never has them
- Centralize credential management across all your agents
- Add policy controls (OPA) and sandboxing without changing agent code

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
```

Your agent makes normal HTTP requests. Veilwarden intercepts them and adds the appropriate `Authorization` header based on the destination host.

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

### Sandbox (Optional)

Run agents in an isolated filesystem sandbox:

```yaml
sandbox:
  enabled: true
  backend: anthropic
  allowed_write_paths: [./project, /tmp]
  denied_read_paths: [~/.ssh, ~/.aws]
```

Requires [srt](https://www.npmjs.com/package/@anthropic-ai/sandbox-runtime): `npm install -g @anthropic-ai/sandbox-runtime`

See [Sandbox Quickstart](docs/sandbox-quickstart.md) for details.

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

**What Veilwarden provides:**
- Secrets injected at network layer, not in application code
- Optional sandbox prevents filesystem access to `~/.ssh`, `~/.aws`, etc.
- Optional OPA policies for fine-grained request control
- `DOPPLER_TOKEN` stripped from child process environment

**Limitations:**
- Other exported env vars are visible to child processes
- Sandbox is experimental (Anthropic srt backend only)
- Policy defaults to allow-all for compatibility

See [SECURITY.md](docs/SECURITY.md) for threat model details.

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
