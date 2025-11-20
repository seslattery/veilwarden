````markdown
# Veilwarden

## EXPERIMENTAL USE ONLY

**Stop putting API keys in your code. Start using zero-trust egress for AI agents and services.**

Veilwarden is a self-hosted HTTP proxy that injects API secrets into outbound requests so your **applications and AI agents** never handle credentials directly.

- For **local AI agents**, it acts as a “tool access broker”: agents call one local proxy, Veilwarden injects keys based on policy.
- For **Kubernetes workloads**, it authenticates with workload identity for secretless access.
- **OPA policies** control exactly which agents/services can call which APIs, paths, and even which query parameters or models.

---

## Why Veilwarden? (AI Agents Front and Center)

### Without Veilwarden (agent or app):

```python
# Secret sprawl across every service and agent
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# Manual rotation breaks everything
# No audit trail of API usage
# Secrets exposed in logs, memory dumps, and prompt injections
# Per-agent/service access control is manual and fragile
````

### With Veilwarden:

```python
# AI agent: just make HTTP requests - secrets injected automatically
response = requests.post("https://api.openai.com/v1/chat/completions", ...)

# Centralized rotation - zero code changes
# Complete audit trail of which agent/workload accessed what
# Secrets never touch application memory
# OPA policies enforce per-agent, per-path, per-model access control
```

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

### Secret Management with Doppler

VeilWarden veil CLI supports two methods for secret management:

#### Option 1: Environment Variables (Default)

Secrets are loaded from environment variables based on the `secret_id` in your routes:

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
veil exec -- python my_agent.py
```

#### Option 2: Doppler Integration

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

**Fallback Behavior**: If Doppler is configured but `DOPPLER_TOKEN` is not set, veil will automatically fall back to loading secrets from environment variables.

For more information, see [Doppler documentation](https://docs.doppler.com/).

#### Security Notes

**Current Limitations:**

1. **Environment Variable Handling**: Only `DOPPLER_TOKEN` is stripped from the child process environment. Other secrets (like `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) remain visible to the agent process if you export them. This is by design for flexibility, but means agents could potentially access these values directly via `os.getenv()`. Future versions may add more aggressive environment sanitization.

2. **Policy Enforcement**: Policies are enforced when configured (see [Policy Configuration](#policy-configuration) below), but default to allow-all for backward compatibility. For production use, always configure `policy.engine: opa` or `policy.engine: config` in your `config.yaml`.

3. **Sandbox Mode**: The `--sandbox` flag is not yet implemented. Attempting to use it will return an error. Track implementation progress in [GitHub Issues](https://github.com/yourusername/veilwarden/issues).

**Best Practices:**

- Use Doppler integration instead of exporting secrets to your shell
- Always configure policy enforcement for production workloads
- Review the [Security Design](docs/plans/2025-11-19-security-fixes-design.md) for threat model details
### Core Benefits

**1. Zero-Trust Security for Agents & Services**
Your agents and applications never see the actual API keys. They make HTTP requests through Veilwarden, which injects credentials based on identity (agent/workload) and policy evaluation. Even if an agent is prompt-injected, it can’t exfiltrate secrets it never had.

**2. Policy-Driven Access Control (with OPA)**
Use Open Policy Agent (OPA) to define fine-grained rules like:

* “Agent `research-assistant` can only call `POST /v1/chat/completions` with `model=gpt-4o-mini`.”
* “Agent `billing-bot` can call Stripe `/v1/payment_intents`, but never `/v1/refunds`.”
* “Production pods can access Stripe production API; staging pods get test keys.”

**3. Kubernetes-Native Identity**
Authenticate workloads using K8s Service Account tokens instead of scattering API keys. Pods prove who they are using existing K8s primitives – no new credential distribution system needed.

**4. Frictionless Developer & Agent Experience**
Developers write agents and services that make normal HTTP requests. No SDK wiring, no env vars for secrets, no secret files to mount. Veilwarden handles authentication and header injection transparently.

**5. Compliance & Auditability**
Every API request flows through a single control plane with centralized logging. Track exactly which agent/workload accessed which external API, when, and whether it was allowed. Rotate secrets in one place without code deployments.

**6. Multi-Tenancy Built-In**
Per-namespace and per-agent policies ensure tenant isolation. Namespace `customer-a` cannot access `customer-b`’s API credentials. OPA policies map Service Account or agent identity to the correct secret.

---

## Quick Start: Local AI Agents (Recommended First)

You’re building an AI agent that needs to call the OpenAI API, but you don’t want to hardcode API keys or give the agent broad, unbounded access.

### 1. Create a config file (`veilwarden.yaml`)

```yaml
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

### 2. Run Veilwarden locally

```bash
export VEILWARDEN_SESSION_SECRET="$(openssl rand -hex 16)"

go run ./cmd/veilwarden --config veilwarden.yaml
# Default: listens on http://127.0.0.1:8088
```

### 3. Point your AI agent at Veilwarden

```python
# ai_agent.py - Zero API keys in code
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

**Result:** The OpenAI API receives your request with the `Authorization: Bearer sk-...` header automatically injected. Your agent code never touched the API key.

---

## Using Real Secret Management (Doppler)

Production systems shouldn’t have secrets in config files. Use Doppler integration:

```bash
# Store your secret in Doppler
doppler secrets set OPENAI_API_KEY --value "sk-your-key"

# Run Veilwarden with Doppler backend
export DOPPLER_TOKEN="dp.st.***"
export DOPPLER_PROJECT="my-project"
export DOPPLER_CONFIG="production"

go run ./cmd/veilwarden \
  --config veilwarden.yaml \
  --doppler-token "$DOPPLER_TOKEN" \
  --doppler-project "$DOPPLER_PROJECT" \
  --doppler-config "$DOPPLER_CONFIG"
```

Secrets are fetched from Doppler on-demand, cached in-memory (default 5m TTL), and rotated without restarting your apps or agents.

---

## Kubernetes Deployment (Agents & Services in Cluster)

Deploy Veilwarden as a DaemonSet so every node runs a local proxy. Pods (agents or services) authenticate using their Service Account tokens.

### 1. Deploy Veilwarden

```bash
kubectl apply -k deploy/kubernetes/
```

### 2. Configure your AI agent pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ai-agent
  namespace: ai-services
spec:
  serviceAccountName: ai-agent-sa
  containers:
  - name: agent
    image: my-ai-agent:latest
    env:
      - name: API_PROXY_URL
        value: "http://localhost:8088"  # Route through Veilwarden
```

### 3. Your agent makes normal HTTP requests (using SA token for identity)

```python
# Application/agent code - no API keys needed
import requests

def call_openai(prompt: str):
    with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
        sa_jwt = f.read()

    return requests.post(
        "http://localhost:8088/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {sa_jwt}",   # workload identity
            "X-Upstream-Host": "api.openai.com",
            "Content-Type": "application/json",
        },
        json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}]},
    )
```

---

## OPA: Locking Down AI Agents by Paths, Models, and Query Params

OPA lets you constrain agents *very* tightly. For example:

* Only allow `ai-agent-sa` to call OpenAI chat completions.
* Only allow specific models (e.g. cheaper models).
* Only allow certain tools/paths; block dangerous ones.
* Restrict query params like `model`, `max_tokens`, etc.

### Example OPA Policy (`policies/ai_agents.rego`)

```rego
package veilwarden.authz

import rego.v1

default allow := false
default deny_reason := "unauthorized"

# Helper: extract query model parameter safely
model_from_query(model) if {
    some i
    input.query[i].key == "model"
    model := input.query[i].value
}

# Allow AI agent to use cheap chat models only
allow if {
    input.namespace == "ai-services"
    input.service_account == "ai-agent-sa"
    input.agent_id == "research-assistant"

    # Only OpenAI chat completions
    input.upstream_host == "api.openai.com"
    input.method == "POST"
    input.path == "/v1/chat/completions"

    # Restrict models (no gpt-4o with $$$ pricing)
    model_from_query(model)
    model in {
        "gpt-4o-mini",
        "gpt-4.1-mini",
    }

    # Optional: limit max_tokens to avoid cost explosions
    some i
    input.query[i].key == "max_tokens"
    to_number(input.query[i].value) <= 2048
}

# Explicitly deny file uploads for agents (tool hardening)
deny if {
    input.namespace == "ai-services"
    input.service_account == "ai-agent-sa"
    input.upstream_host == "api.openai.com"
    input.path == "/v1/files"
}

# Attach human-readable reason
deny_reason := "ai-agent-not-allowed-to-upload-files" if {
    input.namespace == "ai-services"
    input.service_account == "ai-agent-sa"
    input.upstream_host == "api.openai.com"
    input.path == "/v1/files"
}
```

### Policy Input Shape (what Veilwarden sends to OPA)

```json
{
  "method": "POST",
  "path": "/v1/chat/completions",
  "upstream_host": "api.openai.com",
  "namespace": "ai-services",
  "service_account": "ai-agent-sa",
  "agent_id": "research-assistant",
  "query": [
    {"key": "model", "value": "gpt-4o-mini"},
    {"key": "max_tokens", "value": "1024"}
  ],
  "user_id": "alice",
  "user_org": "engineering",
  "request_id": "req-abc123",
  "timestamp": "2025-11-16T12:00:00Z"
}
```

Enable OPA in your config:

```yaml
policy:
  enabled: true
  engine: opa
  policy_path: /etc/veilwarden/policies/
  decision_path: veilwarden/authz/allow
```

---

## How It Works

### Architecture

```text
┌──────────────────────────────┐
│      Your Agent / App Pod    │
│                              │
│   No API keys in env/code    │
└──────────────┬───────────────┘
               │ HTTP request
               │ + SA token (k8s) or session secret (local)
               ▼
┌──────────────────────────────┐
│          Veilwarden          │ (DaemonSet or local dev)
│                              │
│ 1. Authenticate identity     │
│ 2. Build rich OPA input      │───▶ ❌ Deny (403 + reason)
│ 3. Fetch secret from Doppler │     ✅ Allow ──▶ Inject header
│ 4. Inject & forward request  │                 to upstream
└──────────────┬───────────────┘
               │ HTTP + injected API key
               ▼
┌──────────────────────────────┐
│         External API         │
│      (OpenAI, Stripe, ...)   │
└──────────────────────────────┘
```

### Request Flow

1. **Authentication**

   * Local dev: agent proves identity with `X-Session-Secret`.
   * Kubernetes: workload proves identity with Service Account token.

2. **Policy Evaluation (OPA)**
   OPA receives request context (namespace, SA, agent_id, upstream host, method, path, query params, user metadata) and decides `allow` or `deny`, and which `secret_id` to use.

3. **Secret Retrieval**
   If allowed, Veilwarden fetches the mapped secret from Doppler (or static config) and caches it.

4. **Injection & Proxying**
   Secret is injected into the configured header (e.g. `Authorization: Bearer <secret>`), and the request is forwarded to the upstream API.

5. **Response**
   Upstream response is returned unchanged; Veilwarden logs metadata (no secrets) for audit.

---

## Real-World Use Cases

### 1. AI Agents with Strict Guardrails

**Problem:** Your AI agent needs OpenAI, Anthropic, and Perplexity, but you:

* Don’t want secrets in code/env,
* Want to restrict which models and tools it can use,
* Need an audit trail of all external calls.

**Solution:**

* Run Veilwarden locally (or in K8s).
* Route all agent HTTP calls through Veilwarden.
* Use OPA to:

  * Restrict which hosts (OpenAI, Anthropic, Perplexity) it can call,
  * Limit allowed paths (`/v1/chat/completions`, not `/v1/files`),
  * Limit models and cost (e.g. only `gpt-4o-mini` and `claude-3-haiku`),
  * Enforce budgets via `max_tokens` / rate limits (via OPA + external checks).

The agent remains credential-free & controlled purely by policy.

### 2. Multi-Tenant SaaS with Per-Customer Isolation

Each customer has their own Stripe API key (connected accounts). Deploy Veilwarden with OPA policies that map `namespace → customer → secret`. Namespace `customer-a-prod` can only access `stripe-key-customer-a`. Policy enforcement prevents cross-tenant access even if pods are compromised.

### 3. CI/CD Pipelines with GitHub API Access

CI jobs run in K8s and need GitHub tokens for releases, comments, etc. Instead of storing tokens in every repo, CI jobs use a Service Account and call through Veilwarden. OPA policy allows `github-ci-sa` to access `api.github.com` with a specific PAT. Rotating the PAT in Doppler instantly updates all pipelines.

### 4. Microservices Accessing Third-Party APIs

20 microservices need Twilio API credentials. Instead of mounting secrets everywhere and redeploying on rotation:

* Services route Twilio calls through Veilwarden.
* OPA policies define which services may access Twilio.
* Twilio credentials live in Doppler; Veilwarden pulls & injects them.

---

## Features

* **AI Agent–First Design:** Local & K8s patterns to keep agents credential-free with OPA-enforced guardrails.
* **Kubernetes Service Account Authentication:** Workloads authenticate using native K8s identities (SA tokens).
* **Session Secret Authentication:** Local development mode with shared session secrets.
* **OPA Policy Engine:** Fine-grained access control (per identity / path / method / query param / model).
* **Doppler Integration:** Fetch secrets from Doppler with automatic caching.
* **Secret Injection:** Inject secrets into HTTP headers (Authorization, X-API-Key, custom headers).
* **Multiple Upstream Routes:** Configure many third-party APIs with different secrets.
* **Automatic Secret Caching:** In-memory cache with configurable TTL (default 5m).
* **Request Context Enrichment:** Pass user metadata, agent IDs, org context to policies.
* **Health Check Endpoint:** `/healthz` for liveness/readiness probes.
* **Structured Logging:** Logs include request IDs, identity, and upstream metadata (never secrets).

---

## Documentation

* **[OPA Policy Examples](policies/example.rego)** – Sample policies for agents & services.
* **[Kubernetes Deployment Guide](docs/kubernetes-workload-identity.md)** – Complete K8s setup instructions.
* **[Doppler Integration](examples/doppler-config.yaml)** – Configuration examples for Doppler backend.
* **[Local Development](scripts/)** – Helper scripts for local testing with Doppler and OPA.

---

## Development

**Prerequisites:**

* Go 1.25+
* [just](https://github.com/casey/just) command runner (optional but recommended)
* Docker (for building images and E2E tests)
* EnvTest binaries (optional, for integration tests with real K8s API server)

### Quick Setup

```bash
# Install development dependencies
just setup

# Optional: Install EnvTest for integration tests
just install-envtest

# Or manually:
brew install just  # macOS
# or: cargo install just
```

### Common Development Tasks

```bash
# Run tests
just test              # Unit and basic E2E tests
just test-unit         # Fast unit tests only
just test-integration  # With EnvTest (real K8s API server)
just test-e2e          # Kubernetes E2E tests (requires cluster)
just test-all          # All tests
just test-coverage     # Generate coverage report

# Code quality
just lint              # Run golangci-lint
just vuln-check        # Check for vulnerabilities
just fmt               # Format code
just check             # Lint + vuln + test
just check-all         # Lint + vuln + all tests

# Build
just build             # Build binary to bin/veilwarden
just docker-build      # Build Docker image

# Run locally
just run               # Run with example config
just run-doppler       # Run with Doppler integration

# Maintenance
just tidy              # Tidy dependencies
just clean             # Clean build artifacts
```

### Manual Testing

```bash
# Run unit tests
go test ./cmd/veilwarden

# Run with build tags
go test -tags=integration ./cmd/veilwarden  # EnvTest integration
go test -tags=e2e ./cmd/veilwarden          # Kubernetes E2E

# Run specific test
go test -v -run TestE2EOPAIntegration ./cmd/veilwarden

# Full E2E with kind cluster
./scripts/test_k8s_e2e.sh
```

### Demo Scripts

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

## Getting Started

```bash
git clone https://github.com/yourusername/veilwarden
cd veilwarden

# Setup development environment
just setup

# Run locally
just run

# Or manually:
export VEILWARDEN_SESSION_SECRET=dev-secret
go run ./cmd/veilwarden --config examples/veilwarden-local-dev.yaml
```

See example configurations in `examples/` and detailed deployment guides in `docs/`.

---

**Status:** Experimental MVP – expect breaking changes as features evolve.
