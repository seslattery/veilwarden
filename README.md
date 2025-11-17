# Veilwarden

**Stop putting API keys in your code. Start using zero-trust egress.**

Veilwarden is a self-hosted HTTP proxy that injects API secrets into outbound requests so your applications or AI Agents never handle credentials directly. When running on kubernetes, automatically authenticate with workload identity for secretless access. OPA policies control which services access which APIs.

## Why Veilwarden?

**Without Veilwarden:**
```python
# Secret sprawl across every service
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# Manual rotation breaks everything
# No audit trail of API usage
# Secrets exposed in logs, memory dumps
# Per-service access control is manual
```

**With Veilwarden:**
```python
# Just make HTTP requests - secrets injected automatically
response = requests.post("https://api.openai.com/v1/chat/completions", ...)

# Centralized rotation - zero code changes
# Complete audit trail of which workload accessed what
# Secrets never touch application memory
# OPA policies enforce per-namespace access control
```

### Core Benefits

**1. Zero-Trust Security**
Your applications never see the actual API keys. They make HTTP requests through Veilwarden, which injects credentials based on workload identity and policy evaluation. Even if your app is compromised, attackers can't exfiltrate secrets they never had.

**2. Policy-Driven Access Control**
Use Open Policy Agent (OPA) to define fine-grained rules: "production pods can access Stripe production API, staging pods get test keys," or "namespace billing-team can access Stripe, but namespace analytics cannot."

**3. Kubernetes-Native Identity**
Authenticate workloads using Service Account tokens instead of managing API keys. Your pods prove who they are using existing K8s primitives - no new credential distribution system needed.

**4. Frictionless Developer Experience**
Developers write code that makes normal HTTP requests to third-party APIs. No SDKs to configure, no environment variables to set, no secret files to mount. Veilwarden handles authentication transparently.

**5. Compliance & Auditability**
Every API request flows through a single control plane with centralized logging. Track exactly which workload accessed which external API, when, and whether it was allowed. Secret rotation happens in one place without code deployments.

**6. Multi-Tenancy Built-In**
Per-namespace policies ensure tenant isolation. Namespace `customer-a` cannot access `customer-b`'s API credentials. OPA policies map Service Account identity to the correct secret.

## Quick Start: Local Development

Let's say you're building an AI agent that needs to call the OpenAI API, but you don't want to hardcode API keys.

**1. Create a config file** (`veilwarden.yaml`):
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

**2. Run Veilwarden locally:**
```bash
export VEILWARDEN_SESSION_SECRET="$(openssl rand -hex 16)"
go run ./cmd/veilwarden --config veilwarden.yaml
```

**3. Make requests through the proxy:**
```bash
curl -X POST http://127.0.0.1:8088/v1/chat/completions \
  -H "X-Session-Secret: $VEILWARDEN_SESSION_SECRET" \
  -H "X-Upstream-Host: api.openai.com" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

The OpenAI API receives your request with the `Authorization: Bearer sk-...` header automatically injected. Your application code never touched the API key.

### Using Real Secret Management (Doppler)

Production systems shouldn't have secrets in config files. Use Doppler integration:

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

Now secrets are fetched from Doppler on-demand, cached in-memory (default 5m TTL), and rotated without restarting your apps.

## Kubernetes Deployment

Deploy Veilwarden as a DaemonSet so every node runs a local proxy. Pods authenticate using their Service Account tokens.

**1. Deploy Veilwarden:**
```bash
kubectl apply -k deploy/kubernetes/
```

**2. Configure your application pod:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: billing-service
  namespace: production
spec:
  serviceAccountName: billing-sa
  containers:
  - name: app
    image: my-billing-service:latest
    env:
    - name: OPENAI_API_URL
      value: "http://localhost:8088"  # Route through Veilwarden
```

**3. Your application makes normal HTTP requests:**
```python
# Application code - no API keys needed
import requests

response = requests.post(
    "http://localhost:8088/v1/chat/completions",
    headers={
        "Authorization": f"Bearer {open('/var/run/secrets/kubernetes.io/serviceaccount/token').read()}",
        "X-Upstream-Host": "api.openai.com"
    },
    json={"model": "gpt-4", "messages": [...]}
)
```

**4. OPA policy controls access** (`policies/authz.rego`):
```rego
package veilwarden.authz

import rego.v1

default allow := false

# Production namespace can access OpenAI production API
allow if {
    input.namespace == "production"
    input.upstream_host == "api.openai.com"
    input.service_account == "billing-sa"
}

# Staging namespace gets test credentials
allow if {
    input.namespace == "staging"
    input.upstream_host == "api.openai.com"
    # Policy maps to different secret_id for staging
}

# Analytics team cannot access Stripe API
deny if {
    input.namespace == "analytics"
    input.upstream_host == "api.stripe.com"
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

## How It Works

**Architecture:**

```
┌─────────────────┐
│  Your App Pod   │
│                 │
│  No API keys!   │
└────────┬────────┘
         │ HTTP request
         │ + Service Account token
         ▼
┌─────────────────┐
│   Veilwarden    │ (DaemonSet on same node)
│                 │
│ 1. Validate SA  │
│ 2. Eval OPA     │───▶ ❌ Deny (403)
│ 3. Fetch secret │     ✅ Allow ──▶ Inject secret
│ 4. Inject       │                  Forward request
└────────┬────────┘
         │ HTTP + injected API key
         ▼
┌─────────────────┐
│  External API   │
│  (OpenAI, etc)  │
└─────────────────┘
```

**Request Flow:**

1. **Authentication:** Workload proves identity using K8s Service Account token (Kubernetes mode) or session secret (local dev mode)
2. **Policy Evaluation:** OPA receives request context (namespace, service account, upstream host, HTTP method, path, user metadata)
3. **Secret Retrieval:** If allowed, Veilwarden fetches the mapped secret from Doppler (or static config) and caches it
4. **Injection & Proxying:** Secret is injected into configured HTTP header (e.g., `Authorization: Bearer <secret>`) and request is forwarded to upstream API
5. **Response:** Upstream API response is returned to the workload unchanged

**Policy Input:**

OPA policies receive rich context for decision-making:

```json
{
  "method": "POST",
  "path": "/v1/chat/completions",
  "upstream_host": "api.openai.com",
  "namespace": "production",
  "service_account": "billing-sa",
  "user_id": "alice",
  "user_org": "engineering",
  "agent_id": "billing-service-v2",
  "request_id": "req-abc123",
  "timestamp": "2025-11-16T12:00:00Z"
}
```

## Real-World Use Cases

### AI Agents with Multiple API Keys

**Problem:** Your AI agent needs OpenAI, Anthropic, and Perplexity API keys. Hardcoding them or using environment variables exposes secrets in logs and memory.

**Solution with Local Development:**

Configure Veilwarden with routes for each API:

```yaml
# veilwarden.yaml
secrets:
  - id: openai-key
    value: sk-proj-abc123...
  - id: anthropic-key
    value: sk-ant-xyz789...
  - id: perplexity-key
    value: pplx-def456...

routes:
  - upstream_host: api.openai.com
    upstream_scheme: https
    secret_id: openai-key
    inject_header: Authorization
    header_value_template: "Bearer {{secret}}"

  - upstream_host: api.anthropic.com
    upstream_scheme: https
    secret_id: anthropic-key
    inject_header: x-api-key
    header_value_template: "{{secret}}"

  - upstream_host: api.perplexity.ai
    upstream_scheme: https
    secret_id: perplexity-key
    inject_header: Authorization
    header_value_template: "Bearer {{secret}}"
```

Your AI agent code becomes credential-free:

```python
# ai_agent.py - Zero API keys in code
import requests
import os

PROXY_URL = "http://localhost:8088"
SESSION_SECRET = os.getenv("VEILWARDEN_SESSION_SECRET")

def call_openai(prompt):
    return requests.post(
        f"{PROXY_URL}/v1/chat/completions",
        headers={
            "X-Session-Secret": SESSION_SECRET,
            "X-Upstream-Host": "api.openai.com",
            "Content-Type": "application/json"
        },
        json={"model": "gpt-4", "messages": [{"role": "user", "content": prompt}]}
    )

def call_anthropic(prompt):
    return requests.post(
        f"{PROXY_URL}/v1/messages",
        headers={
            "X-Session-Secret": SESSION_SECRET,
            "X-Upstream-Host": "api.anthropic.com",
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        },
        json={"model": "claude-3-opus-20240229", "messages": [{"role": "user", "content": prompt}]}
    )

def call_perplexity(query):
    return requests.post(
        f"{PROXY_URL}/chat/completions",
        headers={
            "X-Session-Secret": SESSION_SECRET,
            "X-Upstream-Host": "api.perplexity.ai",
            "Content-Type": "application/json"
        },
        json={"model": "pplx-70b-online", "messages": [{"role": "user", "content": query}]}
    )

# Your agent logic
response = call_openai("What's the weather?")
print(response.json())
```

**Benefits:**
- ✅ API keys never appear in your code or environment variables
- ✅ Rotate credentials in Veilwarden config without touching agent code
- ✅ Add policy controls later without refactoring
- ✅ Complete audit trail of which APIs your agent called

**Solution with Kubernetes:**

Deploy your AI agent as a pod with Veilwarden handling all credentials:

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
      value: "http://localhost:8088"
```

OPA policy controls which models the agent can access:

```rego
# AI agent can access OpenAI and Anthropic, but not Perplexity
allow if {
    input.namespace == "ai-services"
    input.service_account == "ai-agent-sa"
    input.upstream_host in ["api.openai.com", "api.anthropic.com"]
}

# Restrict to specific models based on cost
allow if {
    input.namespace == "ai-services"
    input.upstream_host == "api.openai.com"
    contains(input.path, "gpt-4o-mini")  # Only cheap model allowed
}
```

Your agent code remains identical - just point to `http://localhost:8088` and pass your Service Account token.

### Multi-Tenant SaaS with Per-Customer Isolation
**Problem:** Each customer has their own Stripe API key (connected accounts). You need to ensure Customer A's pods never access Customer B's Stripe credentials.

**Solution:** Deploy Veilwarden with OPA policies that map namespace → customer → secret. Namespace `customer-a-prod` can only access `stripe-key-customer-a`. Policy enforcement prevents cross-tenant access even if pod is compromised.

### CI/CD Pipelines with GitHub API Access
**Problem:** Your CI pipelines need GitHub tokens to create releases, update PRs, etc. Storing tokens in GitHub Actions secrets spreads credential management across repositories.

**Solution:** CI job pods authenticate using Service Account `github-actions-sa`. OPA policy allows this SA to access `api.github.com`. Centralized secret rotation updates all pipelines simultaneously.

### Microservices Accessing Third-Party APIs
**Problem:** You have 20 microservices that need Twilio API credentials. Each service deployment requires secret mounting, rotation breaks deployments, and there's no audit trail.

**Solution:** Microservices make HTTP requests through Veilwarden. OPA policies define which services can access Twilio (e.g., only `notification-service` and `sms-service`). Rotate Twilio credentials in Doppler - all services get new credentials automatically via cache refresh.

## Features

- **Kubernetes Service Account Authentication:** Workloads authenticate using native K8s identities (SA tokens)
- **Session Secret Authentication:** Local development mode with shared session secrets
- **OPA Policy Engine:** Fine-grained access control with Rego policies
- **Doppler Integration:** Fetch secrets from Doppler secret manager with automatic caching
- **Secret Injection:** Inject secrets into HTTP headers (Authorization, X-API-Key, custom headers)
- **Multiple Upstream Routes:** Configure multiple third-party APIs with different secrets
- **Automatic Secret Caching:** In-memory cache with configurable TTL (default 5m)
- **Request Context Enrichment:** Pass user metadata, agent IDs, organization context to policies
- **Health Check Endpoint:** `/healthz` for Kubernetes liveness/readiness probes
- **Comprehensive Logging:** Structured logs with request IDs for audit trails

## Documentation

- **[OPA Policy Examples](policies/example.rego)** - Sample policies for common scenarios
- **[Kubernetes Deployment Guide](docs/kubernetes-workload-identity.md)** - Complete K8s setup instructions
- **[Doppler Integration](examples/doppler-config.yaml)** - Configuration examples for Doppler backend
- **[Local Development](scripts/)** - Helper scripts for local testing with Doppler and OPA

## Development

**Prerequisites:**
- Go 1.25+
- [just](https://github.com/casey/just) command runner (optional but recommended)
- Docker (for building images and E2E tests)
- EnvTest binaries (optional, for integration tests with real K8s API server)

**Quick Setup:**
```bash
# Install development dependencies
just setup

# Optional: Install EnvTest for integration tests
just install-envtest

# Or manually install:
brew install just  # macOS
# or: cargo install just  # via Rust
```

**Common Development Tasks:**

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

**Manual Testing:**
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

**Demo Scripts:**
```bash
# Basic local echo server demo
./scripts/test_local.sh

# Doppler integration demo
export DOPPLER_TOKEN=dp.st.***
./scripts/test_local_with_doppler.sh

# Full Doppler + OPA demo
./scripts/test_local_with_doppler_and_opa.sh
```

## Getting Started

**Clone and run:**
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

**Status:** Experimental MVP - expect breaking changes as features evolve.
