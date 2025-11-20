# Veilwarden

## EXPERIMENTAL USE ONLY

**Stop putting API keys in your code. Start using zero-trust egress for AI agents and services.**

Veilwarden is a self-hosted HTTP proxy that injects API secrets into outbound requests so your applications and AI agents never handle credentials directly.

---

## Quick Start (Laptop Mode)

```bash
# Install
go install github.com/yourusername/veilwarden/cmd/veil@latest

# Initialize config
veil init

# Set API keys in environment (or use Doppler)
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...

# Run your AI agent through the proxy
veil exec -- python my_agent.py

# Your agent code stays clean - no API keys!
```

The `veil exec` command starts a local MITM proxy, injects environment variables (HTTP_PROXY, CA certs), and runs your command. All HTTPS requests are intercepted and API keys are injected transparently.

---

## Secret Management

### Option 1: Environment Variables (Default)

Secrets are loaded from environment variables based on the `secret_id` in your routes:

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
veil exec -- python my_agent.py
```

### Option 2: Doppler Integration

For centralized secret management, configure Doppler in your `~/.veilwarden/config.yaml`:

```yaml
doppler:
  project: my-project
  config: dev           # e.g., dev, staging, prod
  cache_ttl: 5m        # Optional, default 5m
```

Then set your Doppler token:

```bash
export DOPPLER_TOKEN=dp.st.dev.xxxxx
veil exec -- python my_agent.py
```

**Benefits:**
- Secrets never touch your local environment
- Automatic secret rotation from Doppler
- Centralized secret management across teams
- Per-environment configuration (dev, staging, prod)

**Fallback**: If Doppler is configured but `DOPPLER_TOKEN` is not set, veil automatically falls back to environment variables.

---

## Policy Configuration

Control which requests are allowed using OPA policies. Example `~/.veilwarden/config.yaml`:

```yaml
policy:
  engine: opa
  bundle_path: ~/.veilwarden/policies
  decision_path: veilwarden/authz/allow
```

Example policy (`~/.veilwarden/policies/policy.rego`):

```rego
package veilwarden.authz

import rego.v1

default allow := false

# Allow GET /allowed
allow if {
    input.method == "GET"
    startswith(input.path, "/allowed")
}

# Allow POST to /api/*
allow if {
    input.method == "POST"
    startswith(input.path, "/api/")
}
```

See [OPA Integration Documentation](docs/opa-integration.md) for detailed examples.

---

## Server Mode (Kubernetes)

Deploy Veilwarden as a DaemonSet for Kubernetes workloads:

```yaml
# veilwarden.yaml
secrets:
  - id: openai-key
    value: sk-your-openai-api-key

routes:
  - upstream_host: api.openai.com
    upstream_scheme: https
    secret_id: openai-key
    inject_header: Authorization
    header_value_template: "Bearer {{secret}}"
```

Run the server:

```bash
export VEILWARDEN_SESSION_SECRET="$(openssl rand -hex 16)"
go run ./cmd/veilwarden --config veilwarden.yaml
```

Your application routes requests through Veilwarden:

```python
import os
import requests

PROXY_URL = "http://127.0.0.1:8088"
SESSION_SECRET = os.getenv("VEILWARDEN_SESSION_SECRET")

def call_openai(prompt: str):
    return requests.post(
        f"{PROXY_URL}/v1/chat/completions",
        headers={
            "X-Session-Secret": SESSION_SECRET,
            "X-Upstream-Host": "api.openai.com",
            "Content-Type": "application/json",
        },
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
        },
    )

print(call_openai("Hello!").json())
```

---

## Security Notes

**Current Limitations:**

1. **Environment Variable Handling**: Only `DOPPLER_TOKEN` is stripped from the child process environment. Other secrets remain visible if exported. Use Doppler integration instead of exporting secrets to your shell.

2. **Policy Enforcement**: Policies default to allow-all for backward compatibility. Always configure `policy.engine: opa` or `policy.engine: config` for production.

3. **Sandbox Mode**: The `--sandbox` flag is not yet implemented.

**Best Practices:**

- Use Doppler integration instead of exporting secrets to your shell
- Always configure policy enforcement for production workloads
- Review the [Security Design](docs/plans/2025-11-19-security-fixes-design.md) for threat model details

---

## Features

- **AI Agent-First Design**: Local & K8s patterns to keep agents credential-free
- **Kubernetes Service Account Authentication**: Workloads authenticate using native K8s identities
- **OPA Policy Engine**: Fine-grained access control (per identity/path/method)
- **Doppler Integration**: Fetch secrets from Doppler with automatic caching
- **Secret Injection**: Inject secrets into HTTP headers
- **Multiple Upstream Routes**: Configure many third-party APIs with different secrets
- **Automatic Secret Caching**: In-memory cache with configurable TTL (default 5m)
- **Structured Logging**: Logs include request IDs and metadata (never secrets)

---

## Documentation

- **[OPA Integration](docs/opa-integration.md)** - Complete OPA policy guide with examples
- **[Kubernetes Deployment Guide](docs/kubernetes-workload-identity.md)** - Complete K8s setup
- **[Doppler Integration](examples/doppler-config.yaml)** - Configuration examples
- **[Development Scripts](scripts/)** - Helper scripts for local testing

---

## Development

**Prerequisites:**

- Go 1.25+
- [just](https://github.com/casey/just) command runner (optional but recommended)
- Docker (for building images and E2E tests)

### Quick Setup

```bash
# Install development dependencies
just setup

# Run tests
just test              # Unit and basic E2E tests
just test-all          # All tests including integration

# Code quality
just lint              # Run golangci-lint
just check             # Lint + vuln + test

# Build
just build             # Build binary to bin/veilwarden
just docker-build      # Build Docker image

# Run locally
just run               # Run with example config
just run-doppler       # Run with Doppler integration
```

### Manual Testing

```bash
# Basic local echo server demo
./scripts/test_local.sh

# Doppler integration demo
export DOPPLER_TOKEN=dp.st.***
./scripts/test_local_with_doppler.sh

# Full Doppler + OPA demo
./scripts/test_local_with_doppler_and_opa.sh
```

---

**Status:** Experimental MVP – expect breaking changes as features evolve.
