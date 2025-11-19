# VeilWarden Laptop MITM Proxy - Design & Implementation Plan

**Date**: 2025-11-18
**Status**: Approved
**Author**: VeilWarden Team

## Overview

Transform VeilWarden from a Kubernetes-focused API proxy into a dual-mode system that supports both:

1. **Kubernetes workload identity** (existing functionality)
2. **Laptop MITM proxy** (new) - for local AI agents with transparent credential injection

## Design Goals

- **Zero-knowledge agents**: AI agents have no awareness of API credentials
- **Transparent MITM**: Intercept HTTPS via `HTTP_PROXY` environment variables
- **Per-command lifecycle**: Proxy starts on `veil exec`, stops after command exits
- **Doppler integration**: Continue using Doppler as source of truth for secrets
- **OPA policies**: Restrict API access (hosts, paths, models, tools, query params)
- **Sandbox support**: Integrate with `anthropic/sandbox-runtime` for filesystem isolation
- **No system trust store**: Use per-tool CA environment variables only

## User Experience

### Setup and Usage

```bash
# One-time setup
veil init

# Export Doppler token
export DOPPLER_TOKEN=dp.st.dev.xyz123

# Run AI agent through proxy (credentials injected automatically)
veil exec python my_agent.py

# With sandbox isolation
veil exec --sandbox python untrusted_agent.py
```

### Agent Code (Zero Credential Awareness)

```python
# Inside my_agent.py - NO API keys needed!
import requests

response = requests.post(
    'https://api.openai.com/v1/chat/completions',
    json={
        'model': 'gpt-4o',
        'messages': [{'role': 'user', 'content': 'Hello!'}]
    }
)

# VeilWarden automatically injected: Authorization: Bearer sk-...
print(response.json())
```

### Configuration

```yaml
# ~/.veilwarden/config.yaml
routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

  - host: api.anthropic.com
    secret_id: ANTHROPIC_API_KEY
    header_name: x-api-key
    header_value_template: "{{secret}}"

  - host: api.github.com
    secret_id: GITHUB_TOKEN
    header_name: Authorization
    header_value_template: "token {{secret}}"

policy:
  enabled: true
  engine: opa
  policy_path: ~/.veilwarden/policies
```

### OPA Policy Examples

```rego
# ~/.veilwarden/policies/laptop.rego
package veilwarden.authz

default allow := false

# Allow OpenAI API access
allow if {
    input.upstream_host == "api.openai.com"
    input.method in ["GET", "POST"]
}

# Allow only specific models
allow if {
    input.upstream_host == "api.openai.com"
    input.path == "/v1/chat/completions"

    body := json.unmarshal(input.body)
    body.model in ["gpt-4o-mini", "gpt-4o"]
}

# Block expensive reasoning models
deny if {
    input.upstream_host == "api.openai.com"
    input.path == "/v1/chat/completions"

    body := json.unmarshal(input.body)
    body.model in ["o1", "o1-pro"]
}

# GitHub API read-only
allow if {
    input.upstream_host == "api.github.com"
    input.method in ["GET", "HEAD"]
}
```

## Architecture

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ User runs: veil exec python agent.py                            │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│ CLI: veil exec                                                   │
├─────────────────────────────────────────────────────────────────┤
│ 1. Generate ephemeral CA cert + session ID                      │
│ 2. Start martian proxy on random port (e.g., 127.0.0.1:58392)  │
│ 3. Set environment variables:                                   │
│    - HTTP_PROXY=http://127.0.0.1:58392                          │
│    - HTTPS_PROXY=http://127.0.0.1:58392                         │
│    - REQUESTS_CA_BUNDLE=/tmp/veil-ca-xyz.crt                    │
│    - SSL_CERT_FILE=/tmp/veil-ca-xyz.crt                         │
│    - NODE_EXTRA_CA_CERTS=/tmp/veil-ca-xyz.crt                   │
│ 4. Optionally wrap with sandbox-runtime (--sandbox flag)        │
│ 5. Execute: python agent.py                                     │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Agent: python agent.py                                           │
├─────────────────────────────────────────────────────────────────┤
│ Makes HTTPS request:                                             │
│ requests.post('https://api.openai.com/v1/chat/completions')     │
│                                                                   │
│ HTTP client sees HTTPS_PROXY env var                            │
│ Sends CONNECT to proxy:                                         │
│   CONNECT api.openai.com:443 HTTP/1.1                           │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Martian Proxy                                                    │
├─────────────────────────────────────────────────────────────────┤
│ 6. Intercept CONNECT request                                    │
│ 7. Perform TLS MITM:                                            │
│    - Client ←TLS→ Proxy (using ephemeral CA cert)               │
│    - Proxy ←TLS→ api.openai.com                                 │
│ 8. Decrypt request, parse HTTP                                  │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Policy Modifier (Martian)                                        │
├─────────────────────────────────────────────────────────────────┤
│ 9. Build PolicyInput:                                           │
│    - Method: POST                                                │
│    - UpstreamHost: api.openai.com                               │
│    - Path: /v1/chat/completions                                 │
│    - Body: {"model": "gpt-4o", ...}                             │
│ 10. Call OPA policy engine                                      │
│ 11. If denied → return 403 Forbidden                            │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Secret Injector Modifier (Martian)                              │
├─────────────────────────────────────────────────────────────────┤
│ 12. Lookup route for api.openai.com                            │
│ 13. Fetch secret from Doppler (secret_id: OPENAI_API_KEY)      │
│ 14. Inject header:                                              │
│     Authorization: Bearer sk-proj-xyz123...                     │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Forward to Upstream                                              │
├─────────────────────────────────────────────────────────────────┤
│ 15. Re-encrypt request with real TLS to api.openai.com         │
│ 16. Send modified request with injected Authorization           │
│ 17. Receive response from OpenAI                                │
│ 18. Forward response back to agent                              │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Agent receives response (unaware of proxy)                       │
│ Process exits                                                     │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│ CLI Cleanup                                                      │
├─────────────────────────────────────────────────────────────────┤
│ 19. Stop proxy server                                           │
│ 20. Delete ephemeral CA cert from /tmp                          │
└─────────────────────────────────────────────────────────────────┘
```

### Component Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ veil (CLI)                                                    │
│ ┌──────────────────┐  ┌──────────────────┐  ┌─────────────┐ │
│ │ exec.go          │  │ init.go          │  │ validate.go │ │
│ │ - Start proxy    │  │ - Create config  │  │ - Check cfg │ │
│ │ - Inject env vars│  │ - Example policies│  │ - Test OPA  │ │
│ │ - Exec command   │  │                  │  │             │ │
│ └──────────────────┘  └──────────────────┘  └─────────────┘ │
│           │                                                   │
│           │ Imports                                           │
│           ▼                                                   │
│ ┌────────────────────────────────────────────────────────┐   │
│ │ mitm/                                                   │   │
│ │ - cert.go: Ephemeral CA generation                     │   │
│ │ - sandbox.go: sandbox-runtime integration              │   │
│ └────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
                       │
                       │ Starts
                       ▼
┌──────────────────────────────────────────────────────────────┐
│ veilwarden (Proxy Server)                                    │
│ ┌────────────────────────────────────────────────────────┐   │
│ │ martian_proxy.go                                        │   │
│ │ - NewMartianProxyServer()                              │   │
│ │ - Setup MITM config                                    │   │
│ │ - Register modifiers                                    │   │
│ └────────────────────────────────────────────────────────┘   │
│           │                                                   │
│           │ Uses                                              │
│           ▼                                                   │
│ ┌────────────────────────────────────────────────────────┐   │
│ │ martian_modifiers.go                                    │   │
│ │                                                          │   │
│ │ policyModifier:                                         │   │
│ │   - Build PolicyInput                                   │   │
│ │   - Call PolicyEngine.Decide()                          │   │
│ │   - Return 403 if denied                                │   │
│ │                                                          │   │
│ │ secretInjectorModifier:                                 │   │
│ │   - Lookup route by host                                │   │
│ │   - Fetch secret from secretStore                       │   │
│ │   - Inject into configured header                       │   │
│ └────────────────────────────────────────────────────────┘   │
│           │                                                   │
│           │ Uses (existing components)                        │
│           ▼                                                   │
│ ┌────────────────────────────────────────────────────────┐   │
│ │ policy.go / opa_policy.go (UNCHANGED)                   │   │
│ │ - PolicyEngine interface                                │   │
│ │ - OPA policy evaluation                                 │   │
│ │                                                          │   │
│ │ doppler_store.go (UNCHANGED)                            │   │
│ │ - secretStore interface                                 │   │
│ │ - Doppler API client with caching                       │   │
│ │                                                          │   │
│ │ config.go (UNCHANGED)                                   │   │
│ │ - YAML parsing for routes/secrets                       │   │
│ └────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

## Implementation Details

### CLI Commands

#### `veil exec`

```bash
veil exec [flags] -- <command> [args...]

Flags:
  --sandbox              Enable sandbox-runtime filesystem isolation
  --config PATH          Config file (default: ~/.veilwarden/config.yaml)
  --policy-path PATH     OPA policy directory (overrides config)
  --allow-hosts HOSTS    Comma-separated allowlist (quick policy override)
  --deny-hosts HOSTS     Comma-separated denylist (quick policy override)
  --verbose              Show proxy logs for debugging
  --port PORT            Proxy listen port (default: random)

Examples:
  veil exec -- curl https://api.github.com/user
  veil exec --sandbox -- python agent.py
  veil exec --allow-hosts=api.openai.com -- python agent.py
```

#### `veil init`

```bash
veil init [--config-dir PATH]

Creates:
  ~/.veilwarden/config.yaml         # Route configuration
  ~/.veilwarden/policies/           # OPA policy directory
  ~/.veilwarden/policies/allow.rego # Example allow-all policy
```

#### `veil validate`

```bash
veil validate [--config PATH]

Checks:
  - Config YAML syntax
  - OPA policies compile
  - Doppler connection (if DOPPLER_TOKEN set)
  - Secret IDs referenced in routes exist in Doppler
```

#### `veil test`

```bash
veil test [--config PATH]

Starts proxy interactively, prints:
  - Proxy URL: http://127.0.0.1:58392
  - CA cert path: /tmp/veil-ca-xyz.crt
  - Sample env vars to set manually

User can then test with curl/wget manually
Ctrl-C to stop
```

### Ephemeral CA Generation

```go
// cmd/veil/mitm/cert.go

type EphemeralCA struct {
    CACert     *x509.Certificate
    CAKey      *rsa.PrivateKey
    CertPath   string  // /tmp/veil-ca-<session-id>.crt
    KeyPath    string  // /tmp/veil-ca-<session-id>.key (not used, kept for future)
    sessionID  string
}

func GenerateEphemeralCA(sessionID string) (*EphemeralCA, error) {
    // 1. Generate RSA key for CA (2048-bit)
    caKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, fmt.Errorf("failed to generate CA key: %w", err)
    }

    // 2. Create self-signed CA certificate
    caCert := &x509.Certificate{
        SerialNumber:          big.NewInt(time.Now().Unix()),
        Subject:               pkix.Name{CommonName: "VeilWarden Ephemeral CA " + sessionID[:8]},
        NotBefore:             time.Now(),
        NotAfter:              time.Now().Add(1 * time.Hour), // Short-lived!
        IsCA:                  true,
        KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
        BasicConstraintsValid: true,
    }

    caCertDER, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create CA cert: %w", err)
    }

    // 3. Write to temp directory
    tmpDir := os.TempDir()
    certPath := filepath.Join(tmpDir, fmt.Sprintf("veil-ca-%s.crt", sessionID))

    certFile, err := os.Create(certPath)
    if err != nil {
        return nil, fmt.Errorf("failed to create cert file: %w", err)
    }
    defer certFile.Close()

    if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}); err != nil {
        return nil, fmt.Errorf("failed to encode cert: %w", err)
    }

    parsedCert, _ := x509.ParseCertificate(caCertDER)

    return &EphemeralCA{
        CACert:    parsedCert,
        CAKey:     caKey,
        CertPath:  certPath,
        sessionID: sessionID,
    }, nil
}

func (ca *EphemeralCA) Cleanup() {
    os.Remove(ca.CertPath)
}
```

### Martian Proxy Setup

```go
// cmd/veilwarden/martian_proxy.go

import (
    "github.com/google/martian/v3"
    "github.com/google/martian/v3/mitm"
)

type MartianProxyServer struct {
    proxy         *martian.Proxy
    mitmConfig    *mitm.Config
    sessionID     string
    policyEngine  PolicyEngine
    secretStore   secretStore
    routes        map[string]route
    logger        *slog.Logger
    requireAuth   bool  // false for laptop, true for k8s
}

func NewMartianProxyServer(cfg *ProxyConfig) (*MartianProxyServer, error) {
    // 1. Create MITM config with ephemeral CA
    mc, err := mitm.NewConfig(cfg.CACert, cfg.CAKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create MITM config: %w", err)
    }

    mc.SetValidity(1 * time.Hour)
    mc.SetOrganization("VeilWarden MITM")

    // 2. Create martian proxy
    proxy := martian.NewProxy()
    proxy.SetMITM(mc)
    proxy.SetTimeout(30 * time.Second)

    // 3. Load config and initialize components (reuse existing code)
    appCfg, err := loadAppConfig(cfg.ConfigPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load config: %w", err)
    }

    store := newDopplerSecretStore(&dopplerOptions{
        token:   cfg.DopplerToken,
        project: cfg.DopplerProject,
        config:  cfg.DopplerConfig,
        // ... existing doppler options
    })

    policyEngine := buildPolicyEngine(context.Background(), appCfg.policy)

    s := &MartianProxyServer{
        proxy:        proxy,
        mitmConfig:   mc,
        sessionID:    cfg.SessionID,
        policyEngine: policyEngine,
        secretStore:  store,
        routes:       appCfg.routes,
        logger:       cfg.Logger,
        requireAuth:  cfg.RequireAuth,
    }

    // 4. Register modifiers
    s.registerModifiers()

    return s, nil
}

func (s *MartianProxyServer) registerModifiers() {
    stack := martian.NewStack()

    // Optional authentication (for k8s mode)
    if s.requireAuth {
        stack.AddRequestModifier(&authModifier{
            sessionID: s.sessionID,
            logger:    s.logger,
        })
    }

    // Policy enforcement
    stack.AddRequestModifier(&policyModifier{
        policyEngine: s.policyEngine,
        sessionID:    s.sessionID,
        logger:       s.logger,
    })

    // Secret injection
    stack.AddRequestModifier(&secretInjectorModifier{
        routes:      s.routes,
        secretStore: s.secretStore,
        logger:      s.logger,
    })

    s.proxy.SetRequestModifier(stack)
}

func (s *MartianProxyServer) ListenAndServe(addr string, ready chan<- struct{}) error {
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        return fmt.Errorf("failed to listen: %w", err)
    }

    s.logger.Info("proxy listening", "addr", addr)

    if ready != nil {
        close(ready)
    }

    return s.proxy.Serve(listener)
}
```

### Martian Modifiers

```go
// cmd/veilwarden/martian_modifiers.go

// Policy enforcement modifier
type policyModifier struct {
    policyEngine PolicyEngine
    sessionID    string
    logger       *slog.Logger
}

func (m *policyModifier) ModifyRequest(req *http.Request) error {
    ctx := req.Context()

    // Read and buffer request body for policy evaluation
    var bodyBytes []byte
    if req.Body != nil {
        bodyBytes, _ = io.ReadAll(req.Body)
        req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
    }

    policyInput := PolicyInput{
        Method:       req.Method,
        Path:         req.URL.Path,
        Query:        req.URL.RawQuery,
        UpstreamHost: req.URL.Host,
        SessionID:    m.sessionID,
        Timestamp:    time.Now(),
        Body:         string(bodyBytes),
    }

    decision, err := m.policyEngine.Decide(ctx, &policyInput)
    if err != nil {
        m.logger.Error("policy evaluation failed", "error", err, "host", req.URL.Host)
        return fmt.Errorf("policy error: %w", err)
    }

    if !decision.Allowed {
        m.logger.Warn("policy denied request",
            "host", req.URL.Host,
            "path", req.URL.Path,
            "reason", decision.Reason)
        return fmt.Errorf("forbidden by policy: %s", decision.Reason)
    }

    return nil
}

// Secret injection modifier
type secretInjectorModifier struct {
    routes      map[string]route
    secretStore secretStore
    logger      *slog.Logger
}

func (m *secretInjectorModifier) ModifyRequest(req *http.Request) error {
    ctx := req.Context()
    host := req.URL.Host

    // Strip port if present
    if h, _, err := net.SplitHostPort(host); err == nil {
        host = h
    }

    route, ok := m.routes[host]
    if !ok {
        m.logger.Debug("no route configured for host", "host", host)
        return nil
    }

    secret, err := m.secretStore.Get(ctx, route.secretID)
    if err != nil {
        m.logger.Error("failed to fetch secret",
            "secret_id", route.secretID,
            "host", host,
            "error", err)
        return fmt.Errorf("failed to fetch secret %s: %w", route.secretID, err)
    }

    headerValue := strings.ReplaceAll(route.headerValueTemplate, "{{secret}}", secret)
    req.Header.Set(route.headerName, headerValue)

    m.logger.Info("injected secret",
        "host", host,
        "header", route.headerName,
        "secret_id", route.secretID)

    return nil
}
```

### PolicyInput Extension

```go
// cmd/veilwarden/policy.go

type PolicyInput struct {
    // Request context
    Method       string
    Path         string
    Query        string
    UpstreamHost string

    // Identity context (for k8s mode)
    Namespace      string
    ServiceAccount string
    PodName        string

    // Session context (for laptop mode)
    SessionID string

    // Resource context
    SecretID string

    // Metadata
    Timestamp time.Time

    // NEW: Request body for policy inspection
    Body string  // JSON string for model/tool restriction policies
}
```

## Testing Strategy

### Unit Tests

```go
// cmd/veil/mitm/cert_test.go
func TestGenerateEphemeralCA(t *testing.T) {
    ca, err := GenerateEphemeralCA("test-session-123")
    require.NoError(t, err)
    defer ca.Cleanup()

    // Verify CA cert
    assert.True(t, ca.CACert.IsCA)
    assert.Equal(t, 1*time.Hour, ca.CACert.NotAfter.Sub(ca.CACert.NotBefore))

    // Verify cert file exists
    _, err = os.Stat(ca.CertPath)
    assert.NoError(t, err)

    // Verify cleanup
    ca.Cleanup()
    _, err = os.Stat(ca.CertPath)
    assert.True(t, os.IsNotExist(err))
}
```

### Integration Tests

```go
// cmd/veilwarden/martian_proxy_test.go
func TestMartianProxy_SecretInjection(t *testing.T) {
    // Setup ephemeral CA
    ca, _ := GenerateEphemeralCA("test-session")
    defer ca.Cleanup()

    // Mock upstream server
    mockUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        assert.Equal(t, "Bearer test-secret-value", r.Header.Get("Authorization"))
        w.WriteHeader(http.StatusOK)
    }))
    defer mockUpstream.Close()

    // Start proxy
    proxy, _ := NewMartianProxyServer(&ProxyConfig{
        CACert:      ca.CACert,
        CAKey:       ca.CAKey,
        SessionID:   "test-session",
        Routes:      testRoutes,
        SecretStore: &configSecretStore{secrets: map[string]string{"TEST_SECRET": "test-secret-value"}},
    })

    listener, _ := net.Listen("tcp", "127.0.0.1:0")
    go proxy.Serve(listener)

    // Make request through proxy
    client := &http.Client{
        Transport: &http.Transport{
            Proxy: func(req *http.Request) (*url.URL, error) {
                return url.Parse("http://" + listener.Addr().String())
            },
            TLSClientConfig: &tls.Config{
                RootCAs: createCertPool(ca.CACert),
            },
        },
    }

    resp, err := client.Get(mockUpstream.URL + "/test")
    require.NoError(t, err)
    assert.Equal(t, http.StatusOK, resp.StatusCode)
}
```

### E2E Tests

```go
// cmd/veil/exec_test.go
func TestVeilExec_PythonAgent(t *testing.T) {
    tmpDir := t.TempDir()

    // Create test config
    configPath := filepath.Join(tmpDir, "config.yaml")
    config := `
routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"
policy:
  enabled: false
`
    os.WriteFile(configPath, []byte(config), 0644)

    // Mock OpenAI API
    mockAPI := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        assert.Equal(t, "Bearer sk-test-key", r.Header.Get("Authorization"))
        json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
    }))
    defer mockAPI.Close()

    // Create Python test script
    script := fmt.Sprintf(`
import requests
import os
resp = requests.get('%s/test', verify=os.environ.get('REQUESTS_CA_BUNDLE'))
assert resp.status_code == 200
`, mockAPI.URL)

    scriptPath := filepath.Join(tmpDir, "test.py")
    os.WriteFile(scriptPath, []byte(script), 0755)

    // Run veil exec
    cmd := exec.Command("veil", "exec", "--config", configPath, "--", "python3", scriptPath)
    cmd.Env = append(os.Environ(), "DOPPLER_TOKEN=test")

    output, err := cmd.CombinedOutput()
    assert.NoError(t, err, "Output: %s", output)
}
```

### CI/CD Pipeline

```yaml
# .github/workflows/test.yml
name: Test

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install requests
          go mod download

      - name: Unit tests
        run: go test -v -race -cover ./...

      - name: E2E tests
        run: go test -v -tags=e2e ./cmd/veil/...

      - name: Build binaries
        run: |
          go build -o veil ./cmd/veil
          go build -o veilwarden ./cmd/veilwarden
```

## Implementation Plan

### Phase 1: Core MITM Infrastructure (Week 1)

- [ ] Add `google/martian/v3` dependency to `go.mod`
- [ ] Implement `cmd/veil/mitm/cert.go` (ephemeral CA generation)
- [ ] Create `cmd/veilwarden/martian_proxy.go` (martian proxy server)
- [ ] Implement basic CONNECT handler with MITM
- [ ] Write unit tests for certificate generation
- [ ] Write integration test: proxy intercepts HTTPS and logs request

**Success Criteria**: Can intercept and log HTTPS requests transparently

### Phase 2: Secret Injection (Week 1-2)

- [ ] Implement `secretInjectorModifier` in `cmd/veilwarden/martian_modifiers.go`
- [ ] Implement `policyModifier` in `cmd/veilwarden/martian_modifiers.go`
- [ ] Reuse existing Doppler integration (no code changes)
- [ ] Write integration test: mock Doppler + mock upstream, verify injection
- [ ] Write E2E test: real HTTPS request through proxy with secret

**Success Criteria**: Secrets are fetched from Doppler and injected into headers

### Phase 3: CLI Wrapper (Week 2)

- [ ] Add `spf13/cobra` dependency
- [ ] Implement `cmd/veil/main.go` (cobra app setup)
- [ ] Implement `cmd/veil/exec.go` (exec command)
- [ ] Implement environment variable injection logic
- [ ] Implement proxy lifecycle management (start/stop/cleanup)
- [ ] Write E2E test: `veil exec curl https://api.example.com`
- [ ] Test with Python (requests), Node.js (fetch), curl

**Success Criteria**: `veil exec <command>` works transparently with various HTTP clients

### Phase 4: OPA Policy Extension (Week 2-3)

- [ ] Extend `PolicyInput` struct with `Body` field
- [ ] Implement request body buffering in policy modifier
- [ ] Write example policies for laptop use cases (`examples/laptop-policies/`)
- [ ] Test model restriction policies (block o1, allow gpt-4o)
- [ ] Test tool restriction policies (Claude tool allowlist)

**Success Criteria**: Policies can restrict API access based on request body

### Phase 5: Sandbox Integration (Week 3)

- [ ] Research `anthropic/sandbox-runtime` CLI interface
- [ ] Implement `--sandbox` flag in `veil exec`
- [ ] Implement subprocess wrapper in `cmd/veil/mitm/sandbox.go`
- [ ] Test filesystem restrictions work with proxy
- [ ] Document sandbox usage in quickstart

**Success Criteria**: `veil exec --sandbox` restricts filesystem access

### Phase 6: Additional CLI Commands (Week 3-4)

- [ ] Implement `veil init` command (create config + examples)
- [ ] Implement `veil validate` command (check config/policies/doppler)
- [ ] Implement `veil test` command (interactive proxy debugging)
- [ ] Implement `veil version` command
- [ ] Write tests for all CLI commands

**Success Criteria**: All CLI commands work and are tested

### Phase 7: Documentation (Week 4)

- [ ] Write `docs/laptop-quickstart.md`
- [ ] Write `docs/policies.md` (policy cookbook)
- [ ] Update main `README.md` with laptop use case
- [ ] Write troubleshooting guide
- [ ] Create demo video/GIF
- [ ] Write migration guide

**Success Criteria**: Users can get started without asking questions

### Phase 8: Cleanup & Release (Week 4)

- [ ] Fix security review comments (Authorization header leak, SecretID population)
- [ ] Add deprecation notice to `server.go` (keep for k8s backward compat)
- [ ] Run full test suite
- [ ] Update CHANGELOG
- [ ] Cut v2.0.0 release
- [ ] Publish announcement

**Success Criteria**: Production-ready release

## Dependencies

```go
// go.mod additions
require (
    github.com/google/martian/v3 v3.3.2    // MITM proxy library
    github.com/spf13/cobra v1.8.0          // CLI framework
)

// Existing dependencies (unchanged)
require (
    github.com/open-policy-agent/opa v0.68.0
    k8s.io/api v0.31.1
    k8s.io/client-go v0.31.1
)
```

## Backward Compatibility

### No Breaking Changes for Kubernetes Users

- Keep `veilwarden` binary for Kubernetes deployments
- All existing flags, config, and behavior unchanged
- New martian proxy is opt-in via `--mitm-mode` flag

### Dual Binary Strategy

1. **`veilwarden`** - Kubernetes daemon (existing functionality)
   - Default mode: non-MITM proxy with explicit headers
   - Optional: `--mitm-mode` for HTTPS interception (future)

2. **`veil`** - Laptop CLI wrapper (new)
   - Always uses martian MITM proxy
   - Subcommands: exec, init, validate, test

### Shared Code

```
cmd/
├── veil/           # Laptop CLI (new)
│   └── imports cmd/veilwarden as library
├── veilwarden/     # Shared proxy logic
│   ├── martian_*.go    # New MITM proxy
│   ├── server.go       # Old proxy (deprecated)
│   ├── policy.go       # Shared
│   ├── doppler_*.go    # Shared
│   └── config.go       # Shared
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Per-command proxy lifecycle** | Simple, no daemon management, clean shutdown |
| **Ephemeral CA certs** | No system trust store modification, no sudo required |
| **Martian library** | Battle-tested, handles MITM complexity, modifier pattern fits |
| **Session ID (optional auth)** | Trust localhost by default, support Proxy-Authorization for k8s |
| **Doppler DOPPLER_TOKEN env** | Simple, user controls scope via token permissions |
| **Route config file** | Explicit, same pattern as k8s deployment |
| **OPA for policies** | Reuse existing engine, rich policy language |
| **No tool name in policies** | Security boundary is API access, not which binary calls it |

## Out of Scope (Future Work)

- Long-running daemon mode with `veil start` / `veil stop`
- Automatic system trust store installation
- Convention-based secret routing (host → OPENAI_API_KEY)
- Process tree inspection for identity
- Multi-user laptop support with per-user isolation
- Request/response logging and replay
- HTTP/2 and gRPC support (depends on martian capabilities)

## Security Considerations

### Trust Model

- **Ephemeral CA**: Generated per-invocation, lives in /tmp, cleaned up on exit
- **Localhost binding**: Proxy only accepts connections from 127.0.0.1
- **No persistent trust**: CA cert never installed in system trust store
- **Session isolation**: Each `veil exec` gets unique session ID

### Threat Mitigation

| Threat | Mitigation |
|--------|------------|
| **CA cert theft** | 1-hour validity, ephemeral, auto-cleanup |
| **Proxy port hijacking** | Random port, localhost-only binding |
| **Secret leakage in logs** | Redact secrets in logs, use secret_id references |
| **Policy bypass** | Policy evaluation before secret fetch, fail-closed |
| **Doppler token exposure** | Inherited from env, not persisted, user-controlled scope |

## Performance Considerations

- **Proxy startup**: <100ms (CA generation + proxy bind)
- **MITM overhead**: ~5-10ms per request (TLS decrypt/encrypt)
- **Doppler caching**: 5min TTL (configurable), reduces API calls
- **OPA evaluation**: <1ms (in-memory, compiled policies)

## Monitoring and Observability

- **Structured logging**: JSON logs with correlation IDs
- **Metrics** (future): Request count, latency, policy decisions, secret cache hits
- **Debugging**: `veil test --verbose` for interactive debugging

## Success Metrics

- [ ] AI agents can call OpenAI/Anthropic/GitHub APIs without knowing credentials
- [ ] OPA policies can restrict model usage and tool access
- [ ] `veil exec` works with Python, Node.js, curl, git
- [ ] Sandbox integration restricts filesystem access
- [ ] Documentation allows new users to onboard in <5 minutes
- [ ] Test coverage >80% for new code
- [ ] Zero regressions for Kubernetes deployments

## Conclusion

This design transforms VeilWarden into a powerful dual-mode system:

1. **Kubernetes**: Workload identity with TokenReview + OPA policies (existing)
2. **Laptop**: MITM proxy with transparent credential injection (new)

The laptop mode enables AI agents to operate in a zero-knowledge environment where credentials are centrally managed in Doppler, access is governed by OPA policies, and the developer experience is seamless via the `veil exec` CLI wrapper.

Key benefits:
- ✅ Zero credential exposure to AI agents
- ✅ Fine-grained policy control (models, tools, APIs)
- ✅ Doppler as single source of truth
- ✅ Sandbox integration for untrusted agents
- ✅ Transparent operation (works with any HTTP client)
- ✅ No system modifications (no sudo, no trust store)
- ✅ Clean architecture reusing existing components
