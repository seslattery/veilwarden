Here’s a design / implementation plan you could drop into a doc and hand to eng leads. It’s intentionally scoped for **easiest-possible MVP** with clear seams for future upgrades.

---

# Veilwarden Local MVP – Design & Implementation Plan

## 1. Problem & Goal

### Problem

Local AI agents (CLIs, MCP tools, RAG workers, etc.) running on developer laptops need to call third-party and internal APIs (OpenAI, GitHub, Stripe, internal REST). Today that usually means:

* Long-lived API keys in env vars or config files.
* Keys copied into multiple tools and scripts.
* Zero visibility or policy on which agent uses what, where, and when.

### Goal

Build a **small local proxy** (codename: **Veilwarden**) that:

* Runs on the developer’s laptop.
* Authenticates requests with a **per-session secret**.
* Looks up secrets in **Doppler** and injects them into outbound HTTP requests (headers only).
* Lets AI agents call APIs **without ever seeing the raw API key**.

We optimize for:

1. **Minimum viable complexity** to show value.
2. A design that can be evolved later:

   * OPA policy,
   * richer identity (agents, devices),
   * dynamic/ephemeral credentials,
   * K8s / server workloads.

---

## 2. Scope & Non-Goals

### In-scope (MVP)

* Single binary **local HTTP proxy** written in Go.
* Intended usage: started by Doppler CLI or manually by a developer.
* **HTTP/1.1 only**, no gRPC/WebSockets.
* **Header injection only** (no body/query rewriting).
* **Static** per-host → secret mapping (configured in YAML).
* Authentication to proxy via a **random session secret** set at startup.
* Secrets fetched from **Doppler** using a Doppler access token.
* Proxy binds only to `127.0.0.1` (no remote access).

### Out-of-scope (for this MVP)

* Kubernetes / cluster deployment (that’s a separate track).
* OPA / Rego policies.
* Device posture / attestation, TPM, mTLS to local proxy.
* Dynamic secrets / cloud IAM / OAuth2 flows.
* Multi-user daemon; we assume “one user, one proxy instance”.

---

## 3. Developer Experience (User Story)

**Happy-path UX we want:**

1. Developer logs into Doppler as usual:

   ```bash
   doppler login
   ```

2. Developer chooses a Doppler project/config and starts the local proxy:

   ```bash
   doppler veilwarden up --project my-app --config dev
   ```

3. CLI:

   * Ensures the user is authenticated.
   * Fetches a Doppler API token for `my-app/dev`.
   * Generates a random `SESSION_SECRET`.
   * Starts `veilwarden` with the appropriate flags/env.
   * Prints instructions or exports env vars:

   ```bash
   Veilwarden listening on http://127.0.0.1:8088

   Export these for your agent:
     VEILWARDEN_URL=http://127.0.0.1:8088
     VEILWARDEN_SESSION_SECRET=xxxxx
   ```

4. AI agent (or any local tool) uses the proxy by:

   * Sending requests to `VEILWARDEN_URL`.
   * Including `X-Session-Secret: $VEILWARDEN_SESSION_SECRET`.
   * Indicating the target upstream `X-Upstream-Host: api.stripe.com`.

5. Veilwarden:

   * Validates the session secret.
   * Looks up a route `host → secret_id → header template`.
   * Fetches secret from Doppler.
   * Injects the header, forwards request, returns response.

This is simple enough for an internal demo and real enough for early adopters to try in their AI workflows.

---

## 4. High-level Architecture

### Components

1. **Veilwarden binary** (this repo)

   * Go HTTP server on `127.0.0.1:<port>`.
   * Reads a config file (`veilwarden.yaml`) and CLI flags/environment.
   * Implements a single main endpoint (e.g. `POST /http`) plus health.

2. **Doppler CLI** (existing, with new subcommand)

   * New subcommand `doppler veilwarden up` that:

     * Resolves project/config context.
     * Retrieves a Doppler API token.
     * Generates `SESSION_SECRET`.
     * Spawns `veilwarden` binary with env/flags set.

3. **Doppler API**

   * Used only as a **Secrets backend**:

     * A single endpoint like `GET /v1/secrets/{secret_id}` → `{ value, version }`.
   * (Exact API TBD; we just need a Go client abstraction.)

### Flow Diagram (conceptual)

Developer → Doppler CLI → starts Veilwarden → AI Agent → Veilwarden → Doppler → Upstream API

---

## 5. Detailed Design

### 5.1 Config Format

Simple YAML file (mounted via `--config` flag), e.g. `~/.config/veilwarden.yaml`:

```yaml
listen: "127.0.0.1:8088"

routes:
  - host: "api.stripe.com"
    secret_id: "STRIPE_API_KEY"
    inject_header: "Authorization"
    inject_format: "Bearer {{secret}}"

  - host: "api.github.com"
    secret_id: "GITHUB_PAT"
    inject_header: "Authorization"
    inject_format: "token {{secret}}"
```

* `host`: required; literal hostname (no wildcards in MVP).
* `secret_id`: Doppler secret name/key.
* `inject_header`: HTTP header name to set.
* `inject_format`: string template where `{{secret}}` will be replaced.

### 5.2 Process Startup

`veilwarden` CLI flags (via `cobra` or basic `flag` package):

* `--listen` (default `127.0.0.1:8088`)
* `--config` path (default `$HOME/.config/veilwarden.yaml`)
* `--doppler-token` (required, passed by Doppler CLI)
* `--session-secret` (required)
* Optional:

  * `--project`, `--config-name` (for logging / future policy)
  * `--log-level`

Example:

```bash
veilwarden \
  --listen 127.0.0.1:8088 \
  --config /Users/sean/.config/veilwarden.yaml \
  --doppler-token $DOPPLER_TOKEN \
  --session-secret $SESSION_SECRET
```

### 5.3 HTTP API (Local Proxy)

#### 5.3.1 Request format

For MVP, expose a single endpoint: `POST /http`.

Headers:

* `X-Session-Secret: <SESSION_SECRET>` (required).
* `X-Upstream-Host: api.stripe.com` (required).
* `X-Agent-Id: <optional arbitrary string>`.

Body:

* Raw payload that should be forwarded to upstream.

The HTTP method and path for upstream can be encoded either:

**Option A (simplest)**: keep the same method and path.

* Agent calls `POST http://127.0.0.1:8088/v1/charges` with:

  * `X-Upstream-Host: api.stripe.com`.
* Veilwarden uses:

  * method: `POST`
  * url: `https://api.stripe.com/v1/charges`.

**Option B**: use JSON envelope:

```json
{
  "method": "POST",
  "path": "/v1/charges",
  "headers": {
    "Content-Type": "application/x-www-form-urlencoded"
  },
  "body": "amount=1000&currency=usd&..."
}
```

MVP: **Option A** is much easier to implement and reason about.

#### 5.3.2 Response format

Veilwarden should:

* Return exactly the upstream status code.
* Pass through headers (minus any we intentionally strip).
* Pass through body.

On errors (auth failure, config missing), return a small JSON body:

```json
{
  "error": "UNAUTHORIZED",
  "message": "Invalid session secret"
}
```

### 5.4 Veilwarden Request Handling Logic

Pseudocode:

```go
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
    // 1) Auth: check session secret
    sess := r.Header.Get("X-Session-Secret")
    if sess == "" || sess != s.sessionSecret {
        writeJSON(w, http.StatusUnauthorized, Error{"UNAUTHORIZED", "Invalid session secret"})
        return
    }

    // 2) Resolve upstream host
    host := r.Header.Get("X-Upstream-Host")
    if host == "" {
        writeJSON(w, http.StatusBadRequest, Error{"MISSING_HOST", "X-Upstream-Host required"})
        return
    }

    route, ok := s.routes[host]
    if !ok {
        writeJSON(w, http.StatusForbidden, Error{"HOST_NOT_ALLOWED", "Host not configured"})
        return
    }

    // 3) Fetch secret (with caching)
    secretValue, err := s.secretStore.Get(r.Context(), route.SecretID)
    if err != nil {
        writeJSON(w, http.StatusBadGateway, Error{"SECRET_ERROR", err.Error()})
        return
    }

    // 4) Build outbound request
    upstreamURL := "https://" + host + r.URL.Path
    upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
    if err != nil {
        writeJSON(w, http.StatusInternalServerError, Error{"UPSTREAM_BUILD_ERROR", err.Error()})
        return
    }

    // Copy safe headers
    copySafeHeaders(upstreamReq.Header, r.Header)

    // Inject secret header
    headerValue := strings.ReplaceAll(route.InjectFormat, "{{secret}}", secretValue)
    upstreamReq.Header.Set(route.InjectHeader, headerValue)

    // 5) Do request
    resp, err := s.httpClient.Do(upstreamReq)
    if err != nil {
        writeJSON(w, http.StatusBadGateway, Error{"UPSTREAM_ERROR", err.Error()})
        return
    }
    defer resp.Body.Close()

    // 6) Relay response
    copyResponseHeaders(w.Header(), resp.Header)
    w.WriteHeader(resp.StatusCode)
    io.Copy(w, resp.Body)
}
```

### 5.5 Secret Store Abstraction

Define a simple interface:

```go
type SecretStore interface {
    Get(ctx context.Context, id string) (value string, err error)
}
```

MVP implementation: **DopplerSecretStore** backed by Doppler HTTP API.

* Uses `--doppler-token` (passed from CLI).
* Caches secrets in an in-memory map with TTL (e.g. `github.com/patrickmn/go-cache` or a tiny custom).

```go
type DopplerSecretStore struct {
    client    *http.Client
    token     string
    cache     *cache.Cache // id -> value
    baseURL   string       // e.g. https://api.doppler.com
}

func (d *DopplerSecretStore) Get(ctx context.Context, id string) (string, error) {
    if value, ok := d.cache.Get(id); ok {
        return value.(string), nil
    }

    // Call Doppler API; exact endpoint TBD
    req, _ := http.NewRequestWithContext(ctx, "GET", d.baseURL+"/v1/secrets/"+url.PathEscape(id), nil)
    req.Header.Set("Authorization", "Bearer "+d.token)

    resp, err := d.client.Do(req)
    // ... handle status, parse JSON, extract `value` ...

    d.cache.Set(id, value, 5*time.Minute)
    return value, nil
}
```

Having an interface makes it trivial to later plug in:

* A K8s version,
* A “mock” store for tests,
* Or support non-Doppler stores if ever needed.

### 5.6 Technology Choices

**Language:**

* **Go 1.24+**

  * Already standard at Doppler.
  * Great for HTTP servers, small binaries, and easy distribution.

**Standard libraries:**

* `net/http` for HTTP server/client.
* `crypto/rand` for secure random values (if proxy generates secrets itself).
* `time`, `context`, etc.

**Third-party libraries:**

* **YAML config:**

  * `gopkg.in/yaml.v3` – mature YAML parser.

* **Logging:**

  * `slog`

* **Telemetry:**
  * OTEL

* **In-memory cache:**

  * `github.com/patrickmn/go-cache` or a minimal custom TTL map.

* **CLI (if in this repo):**

  * `github.com/spf13/cobra` (if we want subcommands like `veilwarden server`), but this can also be barebones.

No need for routing libraries (chi/echo) yet; it’s a couple of endpoints.

### 5.7 Security Model

Assumptions:

* Proxy only listens on `127.0.0.1`.
* Local machine is partially trusted; we mainly want to avoid:

  * accidentally hardcoding raw API keys in agents,
  * easy exfil via simple logs/env dumps.

Controls:

* Per-session random secret (`SESSION_SECRET`):

  * Must be provided in `X-Session-Secret` for every request.
  * Generated by Doppler CLI; never written to disk by proxy.

* Doppler token:

  * Passed via env/flag to the proxy.
  * Not exposed to the agent (only the proxy uses it).
  * Scoped to relevant project/config.

* No secrets in logs:

  * We only log secret IDs, not values.
  * We never log `Authorization` or `X-Session-Secret` headers.

* Upstream host allowlist:

  * No arbitrary hostnames; only those in config.
  * Strict TLS hostname verification.

This is **not** full Zero Trust on the endpoint, but it meaningfully reduces the risk of agent code or debugging output leaking long-lived API keys.

---

## 6. Observability & Debuggability

MVP metrics/logging:

* Per request:

  * timestamp, user/project/config (if provided via flags),
  * agent_id (optional),
  * upstream host,
  * secret_id used,
  * status code,
  * latency bucket.

Endpoints:

* `GET /healthz` – returns 200 OK if proxy is running.
* Optionally `GET /readyz` – validates ability to reach Doppler (for dev debugging).

Log format: JSON lines or simple key-value log; keep it easy to grep.

---

## 7. Implementation Plan (Phases)

### Phase 0 – Repo + Skeleton

* Create repo: `veilwarden`.
* Set up:

  * Go module,
  * `main.go` with flag parsing,
  * empty HTTP server with `/healthz`.

**Deliverable:** binary that starts, listens on localhost, responds to `/healthz`.

---

### Phase 1 – Static Config + Simple Proxy (No Doppler)

* Implement YAML config loading.
* Define `Route` struct and host→route map.
* Implement `/http` handler that:

  * Validates `X-Session-Secret`.
  * Picks a route by `X-Upstream-Host`.
  * Injects a **fake** secret from config (e.g. `dummy-secret`) instead of calling Doppler.
  * Forwards request to upstream.

**Deliverable:** end-to-end demo with a hardcoded “secret” string that proves the header injection + forwarding path works.

---

### Phase 2 – Doppler SecretStore Integration

* Implement `SecretStore` interface and `DopplerSecretStore`.
* Define env/flags for:

  * `--doppler-token`,
  * `--doppler-base-url` (default to production).
* Swap fake secret for real `SecretStore.Get()`.
* Add basic in-memory caching.

**Deliverable:**
Local proxy that:

* uses a real Doppler token,
* looks up secrets by ID,
* injects them into headers,
* forwards the request to real APIs (e.g. GitHub).

---

### Phase 3 – Doppler CLI Integration

* Add `doppler veilwarden up` command in the Doppler CLI repo:

  * Discover project/config.
  * Obtain a short-lived Doppler token for that context.
  * Generate `SESSION_SECRET` (`crypto/rand` 32 bytes, base64).
  * Spawn `veilwarden` process with flags/env.
* Optionally write out `VEILWARDEN_URL` and `VEILWARDEN_SESSION_SECRET` into a `.env` file or export them for shell sessions / child processes.

**Deliverable:**
One command that devs run; they don’t need to manually start `veilwarden`.

---

### Phase 4 – Polish & Guardrails

* Proper error messages (JSON format) for:

  * invalid session,
  * unknown host,
  * missing route,
  * Doppler failures.
* Structured logs (include `request_id`).
* Timeouts and sane defaults:

  * upstream HTTP client timeout (e.g. 10s),
  * Doppler API timeout (e.g. 3–5s).
* Basic tests:

  * Config parsing.
  * Route resolution.
  * Happy-path proxying (possibly with a test HTTP server instead of real Stripe).

---

### Phase 5 – Future-ready Hooks (no implementation yet)

Just shape the code so the following are easy to add later:

* **OPA policy hook:**

  * Add a `PolicyEngine` interface:

    ```go
    type PolicyEngine interface {
        Decide(ctx context.Context, input PolicyInput) (PolicyDecision, error)
    }
    ```
  * MVP implementation returns a decision purely from config.
  * Later we can add an OPA-backed implementation without touching handler logic.

* **Extended identity:**

  * Include `User` fields (user ID/email/org) on the `Server` struct, populated by CLI via flags.
  * Pass `Agent-Id` through into logs and (future) policy input.

* **Other transports:**

  * Hide the HTTP forwarding behind a small abstraction so adding gRPC later doesn’t rewrite everything.

---

## 8. Summary

This MVP gives you:

* A tiny Go binary (Veilwarden) that:

  * Authenticates local AI agents via a session secret,
  * Uses Doppler as the source of truth for secrets,
  * Injects secrets into outbound HTTP headers,
  * Prevents agents from ever seeing the raw credentials.

* A clear incremental path to:

  * richer policy (OPA),
  * stronger workload identity,
  * reuse in K8s,
  * support for dynamic/ephemeral credentials.

And it’s simple enough that one person can get a demo working quickly: start the proxy, configure one route (e.g. `api.stripe.com`), and show an AI agent making Stripe API calls with *no API key in its own config*.
