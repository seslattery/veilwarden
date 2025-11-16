An experimental MVP for an identity-aware, policy-driven, secret-injecting egress proxy.

A self-hosted, node-local HTTP proxy for Kubernetes that:

Authenticates workloads by Kubernetes Service Account identity

Evaluates OPA policy to decide if/what secret to use

Fetches a static API key from Doppler and injects it into outbound HTTP headers

So apps call 3rd-party APIs without ever handling the raw secret themselves

## Getting Started

Prerequisites: Go 1.25+.

Create a config file describing upstream routes and fake secrets (Phase 1 uses static secrets from the file). A ready-to-use example (`test-config.yaml`) points at a bundled local echo server:

```yaml
secrets:
  - id: echo-token
    value: demo-token

routes:
  - upstream_host: 127.0.0.1:9090
    upstream_scheme: http
    secret_id: echo-token
    inject_header: Authorization
    header_value_template: "Bearer {{secret}}"
```

Start the echo server in another terminal:

```bash
go run ./cmd/echo
```

Run the proxy (defaults to `127.0.0.1:8088`):

```bash
VEILWARDEN_SESSION_SECRET=dev-secret \
go run ./cmd/veilwarden --config test-config.yaml
```

Verify the health endpoint:

```bash
curl -s localhost:8088/healthz
```

Send a request through the proxy:

```bash
curl -X POST http://127.0.0.1:8088/test \
  -H "X-Session-Secret: dev-secret" \
  -H "X-Upstream-Host: 127.0.0.1:9090" \
  -d 'hello=world'
```

The echo server responds with JSON that includes the injected `Authorization` header so you can verify Phase 1 end-to-end without any external network calls.

### Using Doppler Secrets (Phase 2)

To fetch real secrets from Doppler, provide a Doppler access token **plus** the project/config context. Example using the bundled Doppler config (`examples/doppler-config.yaml`) that proxies to `https://httpbin.org` and injects `X-Api-Key`:

```bash
# 1. Create a secret in your Doppler project/config:
doppler secrets set HTTPBIN_API_KEY --value "demo-secret"

# 2. Start Veilwarden with Doppler credentials:
export VEILWARDEN_SESSION_SECRET="$(openssl rand -hex 16)"
export DOPPLER_TOKEN="dp.st.***"          # or VEILWARDEN_DOPPLER_TOKEN
export DOPPLER_PROJECT="my-project"       # or VEILWARDEN_DOPPLER_PROJECT
export DOPPLER_CONFIG="dev"               # or VEILWARDEN_DOPPLER_CONFIG

go run ./cmd/veilwarden \
  --config examples/doppler-config.yaml \
  --doppler-token "$DOPPLER_TOKEN" \
  --doppler-project "$DOPPLER_PROJECT" \
  --doppler-config "$DOPPLER_CONFIG"

# 3. Exercise the route (httpbin echoes headers back):
curl -s http://127.0.0.1:8088/headers \
  -H "X-Session-Secret: $VEILWARDEN_SESSION_SECRET" \
  -H "X-Upstream-Host: httpbin.org" | jq '.headers."X-Api-Key"'
```

Flags/env worth knowing:

- `--doppler-token`, `--doppler-project`, `--doppler-config`
- `--doppler-base-url` (defaults to `https://api.doppler.com`, handy for staging/self-hosted Doppler)
- `--secret-cache-ttl` to adjust the in-memory cache duration (default 5m)
- `--doppler-timeout` to tune the Doppler HTTP client timeout (default 5s)

### One-command Local Demo

You can also spin everything up (echo server, proxy, and sample request) with a single helper script:

```bash
./scripts/test_local.sh
```

It streams the echo/proxy logs to temporary files (paths printed on exit) and performs the same `curl` request shown above. Tweak behavior with environment variables:

- `SESSION_SECRET` – overrides the default session secret (`dev-secret`).
- `ECHO_PORT`/`ECHO_ADDR` – choose the local echo server port or address if `127.0.0.1:9090` is unavailable.
- `DOPPLER_TOKEN`, `DOPPLER_PROJECT`, `DOPPLER_CONFIG` – switch the proxy to Doppler-backed secrets instead of the generated config file.

### Local Demo + Doppler

To exercise Doppler secret retrieval against the local echo server, export your Doppler credentials (matching the Veilwarden CLI flags) and run:

```bash
export DOPPLER_TOKEN=dp.st.***
export DOPPLER_PROJECT=veilwarden
export DOPPLER_CONFIG=dev_personal

./scripts/test_local_with_doppler.sh
```

The script:

- ensures a secret named `ECHO_DOPPLER_SECRET` exists in Doppler (value defaults to `demo-secret`, override via `ECHO_SECRET_VALUE`);
- starts the echo server and Veilwarden with the Doppler secret store;
- sends a sample request and prints the echo response so you can confirm the injected `X-Doppler-Secret` header.

`DOPPLER_PROJECT` and `DOPPLER_CONFIG` default to `veilwarden` / `dev_personal` if unset; override them if your Doppler context differs. `DOPPLER_TOKEN` always needs to be exported.

### Local Demo + Doppler + OPA

To test the full integration of Doppler secret management and OPA policy enforcement:

```bash
export DOPPLER_TOKEN=dp.st.***
export DOPPLER_PROJECT=veilwarden
export DOPPLER_CONFIG=dev_personal

./scripts/test_local_with_doppler_and_opa.sh
```

This script demonstrates:

- **Doppler secret retrieval** with automatic cache management
- **OPA policy enforcement** using policies from `policies/` directory
- **Multiple test scenarios**:
  - ✅ Allowed GET request from engineering user
  - ✅ Allowed POST to GitHub API from ci-agent
  - ❌ Denied POST from unknown agent
  - ❌ Denied DELETE request

The script runs with a default user context (`alice` from `engineering` org). To test different access patterns:

```bash
USER_ID=bob USER_EMAIL=bob@external.com USER_ORG=external \
  ./scripts/test_local_with_doppler_and_opa.sh
```

All test responses are saved to `/tmp/veilwarden-opa-*.txt` for inspection.

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

## Testing

### Unit Tests

Run the standard unit tests:

```bash
go test ./cmd/veilwarden
```

### End-to-End Tests

Comprehensive e2e tests that spin up real proxy and echo servers:

```bash
# Run all e2e tests (skips Doppler tests if DOPPLER_TOKEN not set)
go test -v -run TestE2E ./cmd/veilwarden

# Run specific e2e test
go test -v -run TestE2EBasicProxy ./cmd/veilwarden
go test -v -run TestE2EOPAIntegration ./cmd/veilwarden
```

Available e2e tests:

- **TestE2EBasicProxy** - Tests basic proxy functionality with secret injection
- **TestE2EDopplerIntegration** - Tests Doppler secret retrieval (requires DOPPLER_TOKEN)
- **TestE2EOPAIntegration** - Tests OPA policy enforcement with multiple scenarios
- **TestE2EDopplerWithOPA** - Tests full Doppler + OPA integration (requires DOPPLER_TOKEN)

To run Doppler integration tests:

```bash
export DOPPLER_TOKEN=dp.st.***
export DOPPLER_PROJECT=veilwarden
export DOPPLER_CONFIG=dev_personal

go test -v -run TestE2EDoppler ./cmd/veilwarden
```

The e2e tests automatically:
- Find free ports for servers
- Start echo and proxy servers
- Wait for servers to be ready
- Execute test requests
- Clean up resources on completion
