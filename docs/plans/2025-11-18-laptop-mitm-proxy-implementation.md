# Laptop MITM Proxy Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Transform VeilWarden into a dual-mode system supporting both Kubernetes workload identity and laptop MITM proxy for local AI agents with transparent credential injection.

**Architecture:** Add google/martian MITM proxy with modifier pattern for policy enforcement and secret injection. Create `veil` CLI wrapper that generates ephemeral CA certs, starts proxy per-command, injects environment variables, and optionally wraps with sandbox-runtime.

**Tech Stack:** Go 1.21+, google/martian/v3 (MITM), spf13/cobra (CLI), Open Policy Agent, Doppler API

---

## Prerequisites

Before starting, ensure:
- Go 1.21+ installed
- Python 3.11+ installed (for E2E tests)
- `DOPPLER_TOKEN` environment variable set (for integration tests)
- Existing VeilWarden codebase knowledge (policy engine, doppler store, config)

---

## Task 1: Add Dependencies

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

**Step 1: Add google/martian dependency**

```bash
go get github.com/google/martian/v3@v3.3.2
```

Expected: `go.mod` and `go.sum` updated with martian dependency

**Step 2: Add spf13/cobra dependency**

```bash
go get github.com/spf13/cobra@v1.8.0
```

Expected: `go.mod` and `go.sum` updated with cobra dependency

**Step 3: Run go mod tidy**

```bash
go mod tidy
```

Expected: Clean module file with all dependencies

**Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "deps: add google/martian and spf13/cobra for MITM proxy"
```

---

## Task 2: Ephemeral CA Certificate Generation

**Files:**
- Create: `cmd/veil/mitm/cert.go`
- Create: `cmd/veil/mitm/cert_test.go`

**Step 1: Write the failing test**

Create `cmd/veil/mitm/cert_test.go`:

```go
package mitm

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateEphemeralCA(t *testing.T) {
	sessionID := "test-session-123"

	ca, err := GenerateEphemeralCA(sessionID)
	require.NoError(t, err)
	defer ca.Cleanup()

	// Verify CA cert properties
	assert.True(t, ca.CACert.IsCA, "certificate should be CA")
	assert.NotNil(t, ca.CAKey, "CA key should be generated")

	// Verify validity period is 1 hour
	validity := ca.CACert.NotAfter.Sub(ca.CACert.NotBefore)
	assert.Equal(t, 1*time.Hour, validity, "CA should be valid for 1 hour")

	// Verify cert file exists
	_, err = os.Stat(ca.CertPath)
	assert.NoError(t, err, "cert file should exist")

	// Verify cleanup removes cert
	ca.Cleanup()
	_, err = os.Stat(ca.CertPath)
	assert.True(t, os.IsNotExist(err), "cert file should be removed after cleanup")
}

func TestGenerateEphemeralCA_UniqueCerts(t *testing.T) {
	ca1, err := GenerateEphemeralCA("session-1")
	require.NoError(t, err)
	defer ca1.Cleanup()

	ca2, err := GenerateEphemeralCA("session-2")
	require.NoError(t, err)
	defer ca2.Cleanup()

	// Verify different sessions get different certs
	assert.NotEqual(t, ca1.CertPath, ca2.CertPath, "different sessions should have different cert paths")
	assert.NotEqual(t, ca1.CACert.SerialNumber, ca2.CACert.SerialNumber, "different sessions should have different serial numbers")
}
```

**Step 2: Run test to verify it fails**

```bash
go test -v ./cmd/veil/mitm/...
```

Expected: FAIL - package or function not found

**Step 3: Create directory structure**

```bash
mkdir -p cmd/veil/mitm
```

**Step 4: Write minimal implementation**

Create `cmd/veil/mitm/cert.go`:

```go
package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// EphemeralCA represents a short-lived certificate authority for MITM.
type EphemeralCA struct {
	CACert    *x509.Certificate
	CAKey     *rsa.PrivateKey
	CertPath  string
	sessionID string
}

// GenerateEphemeralCA creates a new ephemeral CA certificate and key.
// The certificate is valid for 1 hour and is written to a temp file.
func GenerateEphemeralCA(sessionID string) (*EphemeralCA, error) {
	// Generate RSA key for CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create self-signed CA certificate
	caCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("VeilWarden Ephemeral CA %s", sessionID[:8]),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA cert: %w", err)
	}

	// Parse the DER-encoded certificate
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA cert: %w", err)
	}

	// Write cert to temp file
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

	return &EphemeralCA{
		CACert:    caCert,
		CAKey:     caKey,
		CertPath:  certPath,
		sessionID: sessionID,
	}, nil
}

// Cleanup removes the temporary CA certificate file.
func (ca *EphemeralCA) Cleanup() {
	if ca.CertPath != "" {
		os.Remove(ca.CertPath)
	}
}
```

**Step 5: Run test to verify it passes**

```bash
go test -v ./cmd/veil/mitm/...
```

Expected: PASS - all tests pass

**Step 6: Commit**

```bash
git add cmd/veil/mitm/
git commit -m "feat: implement ephemeral CA certificate generation for MITM

Add EphemeralCA type that generates short-lived (1 hour) self-signed
CA certificates for TLS interception. Certificates are written to temp
files and automatically cleaned up.

Includes comprehensive unit tests for generation and cleanup."
```

---

## Task 3: Martian Proxy Server Setup

**Files:**
- Create: `cmd/veilwarden/martian_proxy.go`
- Create: `cmd/veilwarden/martian_proxy_test.go`

**Step 1: Write the failing test**

Create `cmd/veilwarden/martian_proxy_test.go`:

```go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMartianProxyServer_BasicMITM(t *testing.T) {
	// Generate ephemeral CA for test
	sessionID := "test-session"

	// Mock upstream server
	requestReceived := false
	mockUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestReceived = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockUpstream.Close()

	// Create proxy config
	cfg := &MartianProxyConfig{
		SessionID:   sessionID,
		RequireAuth: false,
	}

	proxy, err := NewMartianProxyServer(cfg)
	require.NoError(t, err)

	// Start proxy on random port
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer proxyListener.Close()

	proxyURL := "http://" + proxyListener.Addr().String()

	go proxy.Serve(proxyListener)

	// Create HTTP client configured to use proxy
	proxyURLParsed, _ := url.Parse(proxyURL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURLParsed),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // For testing only
			},
		},
	}

	// Make request through proxy
	resp, err := client.Get(mockUpstream.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, requestReceived, "request should reach upstream server")
}
```

**Step 2: Run test to verify it fails**

```bash
go test -v ./cmd/veilwarden/ -run TestMartianProxyServer
```

Expected: FAIL - MartianProxyConfig or NewMartianProxyServer not found

**Step 3: Write minimal implementation**

Create `cmd/veilwarden/martian_proxy.go`:

```go
package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"

	"github.com/google/martian/v3"
	"github.com/google/martian/v3/mitm"
)

// MartianProxyConfig holds configuration for the Martian MITM proxy.
type MartianProxyConfig struct {
	SessionID   string
	CACert      *x509.Certificate
	CAKey       *rsa.PrivateKey
	RequireAuth bool
	Logger      *slog.Logger
}

// MartianProxyServer wraps a Martian proxy with VeilWarden configuration.
type MartianProxyServer struct {
	proxy       *martian.Proxy
	mitmConfig  *mitm.Config
	sessionID   string
	requireAuth bool
	logger      *slog.Logger
}

// NewMartianProxyServer creates a new Martian MITM proxy server.
func NewMartianProxyServer(cfg *MartianProxyConfig) (*MartianProxyServer, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Create Martian proxy
	proxy := martian.NewProxy()

	// If CA cert provided, setup MITM
	if cfg.CACert != nil && cfg.CAKey != nil {
		mc, err := mitm.NewConfig(cfg.CACert, cfg.CAKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create MITM config: %w", err)
		}

		mc.SetValidity(1 * time.Hour)
		mc.SetOrganization("VeilWarden MITM")

		proxy.SetMITM(mc)
	}

	proxy.SetTimeout(30 * time.Second)

	return &MartianProxyServer{
		proxy:       proxy,
		sessionID:   cfg.SessionID,
		requireAuth: cfg.RequireAuth,
		logger:      cfg.Logger,
	}, nil
}

// Serve starts the proxy server on the given listener.
func (s *MartianProxyServer) Serve(listener net.Listener) error {
	s.logger.Info("martian proxy listening", "addr", listener.Addr().String())
	return s.proxy.Serve(listener)
}
```

**Step 4: Add missing import**

In `cmd/veilwarden/martian_proxy.go`, ensure imports include:

```go
import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/google/martian/v3"
	"github.com/google/martian/v3/mitm"
)
```

**Step 5: Run test to verify it passes**

```bash
go test -v ./cmd/veilwarden/ -run TestMartianProxyServer
```

Expected: PASS

**Step 6: Commit**

```bash
git add cmd/veilwarden/martian_proxy.go cmd/veilwarden/martian_proxy_test.go
git commit -m "feat: add Martian MITM proxy server wrapper

Implement MartianProxyServer that wraps google/martian proxy with
VeilWarden configuration. Supports optional CA cert for TLS MITM.

Includes basic integration test for proxy functionality."
```

---

## Task 4: Policy Enforcement Modifier

**Files:**
- Create: `cmd/veilwarden/martian_modifiers.go`
- Modify: `cmd/veilwarden/martian_proxy.go`
- Modify: `cmd/veilwarden/martian_proxy_test.go`

**Step 1: Write the failing test**

Add to `cmd/veilwarden/martian_proxy_test.go`:

```go
func TestPolicyModifier_AllowedRequest(t *testing.T) {
	// Create allow-all policy engine
	policyEngine := newConfigPolicyEngine(policyConfig{
		Enabled:      true,
		DefaultAllow: true,
	})

	modifier := &policyModifier{
		policyEngine: policyEngine,
		sessionID:    "test-session",
		logger:       slog.Default(),
	}

	req := httptest.NewRequest("GET", "https://api.openai.com/v1/models", nil)

	err := modifier.ModifyRequest(req)
	assert.NoError(t, err, "allow-all policy should allow request")
}

func TestPolicyModifier_DeniedRequest(t *testing.T) {
	// Create deny-all policy engine
	policyEngine := newConfigPolicyEngine(policyConfig{
		Enabled:      true,
		DefaultAllow: false,
	})

	modifier := &policyModifier{
		policyEngine: policyEngine,
		sessionID:    "test-session",
		logger:       slog.Default(),
	}

	req := httptest.NewRequest("GET", "https://api.openai.com/v1/models", nil)

	err := modifier.ModifyRequest(req)
	assert.Error(t, err, "deny-all policy should deny request")
	assert.Contains(t, err.Error(), "forbidden by policy")
}
```

**Step 2: Run test to verify it fails**

```bash
go test -v ./cmd/veilwarden/ -run TestPolicyModifier
```

Expected: FAIL - policyModifier not found

**Step 3: Write implementation**

Create `cmd/veilwarden/martian_modifiers.go`:

```go
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// policyModifier enforces OPA policies on requests.
type policyModifier struct {
	policyEngine PolicyEngine
	sessionID    string
	logger       *slog.Logger
}

// ModifyRequest enforces policy on the request.
func (m *policyModifier) ModifyRequest(req *http.Request) error {
	ctx := req.Context()

	// Read and buffer request body for policy evaluation
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		// Restore body for downstream handlers
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Extract host (strip port if present)
	host := req.URL.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Build policy input
	policyInput := PolicyInput{
		Method:       req.Method,
		Path:         req.URL.Path,
		Query:        req.URL.RawQuery,
		UpstreamHost: host,
		SessionID:    m.sessionID,
		Timestamp:    time.Now(),
		Body:         string(bodyBytes),
	}

	// Evaluate policy
	decision, err := m.policyEngine.Decide(ctx, &policyInput)
	if err != nil {
		m.logger.Error("policy evaluation failed",
			"error", err,
			"host", host,
			"path", req.URL.Path)
		return fmt.Errorf("policy error: %w", err)
	}

	if !decision.Allowed {
		m.logger.Warn("policy denied request",
			"host", host,
			"path", req.URL.Path,
			"method", req.Method,
			"reason", decision.Reason)
		return fmt.Errorf("forbidden by policy: %s", decision.Reason)
	}

	m.logger.Debug("policy allowed request",
		"host", host,
		"path", req.URL.Path)

	return nil
}
```

**Step 4: Update PolicyInput struct**

Modify `cmd/veilwarden/policy.go` to add Body field:

```go
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

	// Request body for policy inspection (NEW)
	Body string
}
```

**Step 5: Update OPA policy input**

Modify `cmd/veilwarden/opa_policy.go` to include body in OPA input:

Find the line creating the input map (around line 109) and add:

```go
"body": input.Body,
```

**Step 6: Run test to verify it passes**

```bash
go test -v ./cmd/veilwarden/ -run TestPolicyModifier
```

Expected: PASS

**Step 7: Commit**

```bash
git add cmd/veilwarden/martian_modifiers.go cmd/veilwarden/policy.go cmd/veilwarden/opa_policy.go cmd/veilwarden/martian_proxy_test.go
git commit -m "feat: add policy enforcement modifier for Martian

Implement policyModifier that enforces OPA policies on proxied requests.
Buffers request body for policy evaluation while preserving it for
downstream handlers.

Extended PolicyInput with Body field for model/tool restriction policies.
Updated OPA integration to pass request body to policy engine."
```

---

## Task 5: Secret Injection Modifier

**Files:**
- Modify: `cmd/veilwarden/martian_modifiers.go`
- Modify: `cmd/veilwarden/martian_proxy_test.go`

**Step 1: Write the failing test**

Add to `cmd/veilwarden/martian_proxy_test.go`:

```go
func TestSecretInjectorModifier_InjectsSecret(t *testing.T) {
	// Create mock secret store
	secretStore := &configSecretStore{
		secrets: map[string]string{
			"OPENAI_API_KEY": "sk-test-secret-12345",
		},
	}

	// Create routes
	routes := map[string]route{
		"api.openai.com": {
			upstreamHost:        "api.openai.com",
			secretID:            "OPENAI_API_KEY",
			headerName:          "Authorization",
			headerValueTemplate: "Bearer {{secret}}",
		},
	}

	modifier := &secretInjectorModifier{
		routes:      routes,
		secretStore: secretStore,
		logger:      slog.Default(),
	}

	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", nil)

	err := modifier.ModifyRequest(req)
	assert.NoError(t, err)

	// Verify secret was injected
	assert.Equal(t, "Bearer sk-test-secret-12345", req.Header.Get("Authorization"))
}

func TestSecretInjectorModifier_NoRouteConfigured(t *testing.T) {
	modifier := &secretInjectorModifier{
		routes:      map[string]route{},
		secretStore: &configSecretStore{secrets: map[string]string{}},
		logger:      slog.Default(),
	}

	req := httptest.NewRequest("GET", "https://unknown.example.com/test", nil)

	err := modifier.ModifyRequest(req)
	assert.NoError(t, err, "should pass through without error")
	assert.Empty(t, req.Header.Get("Authorization"), "should not inject header")
}
```

**Step 2: Run test to verify it fails**

```bash
go test -v ./cmd/veilwarden/ -run TestSecretInjectorModifier
```

Expected: FAIL - secretInjectorModifier not found

**Step 3: Write implementation**

Add to `cmd/veilwarden/martian_modifiers.go`:

```go
// secretInjectorModifier injects API credentials from secret store.
type secretInjectorModifier struct {
	routes      map[string]route
	secretStore secretStore
	logger      *slog.Logger
}

// ModifyRequest injects the appropriate secret into the request headers.
func (m *secretInjectorModifier) ModifyRequest(req *http.Request) error {
	ctx := req.Context()

	// Extract host (strip port if present)
	host := req.URL.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Lookup route for this host
	route, ok := m.routes[host]
	if !ok {
		// No route configured - pass through without modification
		m.logger.Debug("no route configured for host", "host", host)
		return nil
	}

	// Fetch secret from store
	secret, err := m.secretStore.Get(ctx, route.secretID)
	if err != nil {
		m.logger.Error("failed to fetch secret",
			"secret_id", route.secretID,
			"host", host,
			"error", err)
		return fmt.Errorf("failed to fetch secret %s: %w", route.secretID, err)
	}

	// Inject secret into header
	headerValue := strings.ReplaceAll(route.headerValueTemplate, "{{secret}}", secret)
	req.Header.Set(route.headerName, headerValue)

	m.logger.Info("injected secret",
		"host", host,
		"header", route.headerName,
		"secret_id", route.secretID)

	return nil
}
```

**Step 4: Run test to verify it passes**

```bash
go test -v ./cmd/veilwarden/ -run TestSecretInjectorModifier
```

Expected: PASS

**Step 5: Commit**

```bash
git add cmd/veilwarden/martian_modifiers.go cmd/veilwarden/martian_proxy_test.go
git commit -m "feat: add secret injection modifier for Martian

Implement secretInjectorModifier that fetches secrets from secret store
and injects them into configured headers. Supports template-based header
values with {{secret}} placeholder.

Gracefully handles missing routes (pass-through without injection)."
```

---

## Task 6: Integrate Modifiers with Proxy

**Files:**
- Modify: `cmd/veilwarden/martian_proxy.go`
- Modify: `cmd/veilwarden/martian_proxy_test.go`

**Step 1: Write the failing E2E test**

Add to `cmd/veilwarden/martian_proxy_test.go`:

```go
func TestMartianProxyServer_E2E_SecretInjectionAndPolicy(t *testing.T) {
	// Setup: Create ephemeral CA (we'll implement this helper)
	sessionID := "e2e-test-session"

	// Mock upstream that verifies secret was injected
	var receivedAuth string
	mockUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockUpstream.Close()

	// Extract host from mock upstream URL
	upstreamURL, _ := url.Parse(mockUpstream.URL)
	upstreamHost := upstreamURL.Host
	if h, _, err := net.SplitHostPort(upstreamHost); err == nil {
		upstreamHost = h
	}

	// Configure proxy with routes and secrets
	routes := map[string]route{
		upstreamHost: {
			upstreamHost:        upstreamHost,
			secretID:            "TEST_SECRET",
			headerName:          "Authorization",
			headerValueTemplate: "Bearer {{secret}}",
		},
	}

	secretStore := &configSecretStore{
		secrets: map[string]string{
			"TEST_SECRET": "sk-e2e-test-secret",
		},
	}

	policyEngine := newConfigPolicyEngine(policyConfig{
		Enabled:      true,
		DefaultAllow: true,
	})

	// Create and start proxy
	cfg := &MartianProxyConfig{
		SessionID:    sessionID,
		RequireAuth:  false,
		Routes:       routes,
		SecretStore:  secretStore,
		PolicyEngine: policyEngine,
	}

	proxy, err := NewMartianProxyServer(cfg)
	require.NoError(t, err)

	proxyListener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer proxyListener.Close()

	go proxy.Serve(proxyListener)

	// Make request through proxy
	proxyURL, _ := url.Parse("http://" + proxyListener.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Get(mockUpstream.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "Bearer sk-e2e-test-secret", receivedAuth, "secret should be injected")
}
```

**Step 2: Run test to verify it fails**

```bash
go test -v ./cmd/veilwarden/ -run TestMartianProxyServer_E2E
```

Expected: FAIL - Routes, SecretStore, PolicyEngine fields not in config

**Step 3: Update MartianProxyConfig**

Modify `cmd/veilwarden/martian_proxy.go`:

```go
// MartianProxyConfig holds configuration for the Martian MITM proxy.
type MartianProxyConfig struct {
	SessionID    string
	CACert       *x509.Certificate
	CAKey        *rsa.PrivateKey
	RequireAuth  bool
	Routes       map[string]route       // NEW
	SecretStore  secretStore            // NEW
	PolicyEngine PolicyEngine           // NEW
	Logger       *slog.Logger
}
```

**Step 4: Implement modifier registration**

Update `NewMartianProxyServer` in `cmd/veilwarden/martian_proxy.go`:

```go
func NewMartianProxyServer(cfg *MartianProxyConfig) (*MartianProxyServer, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Create Martian proxy
	proxy := martian.NewProxy()

	// If CA cert provided, setup MITM
	if cfg.CACert != nil && cfg.CAKey != nil {
		mc, err := mitm.NewConfig(cfg.CACert, cfg.CAKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create MITM config: %w", err)
		}

		mc.SetValidity(1 * time.Hour)
		mc.SetOrganization("VeilWarden MITM")

		proxy.SetMITM(mc)
	}

	proxy.SetTimeout(30 * time.Second)

	s := &MartianProxyServer{
		proxy:        proxy,
		sessionID:    cfg.SessionID,
		requireAuth:  cfg.RequireAuth,
		policyEngine: cfg.PolicyEngine,
		secretStore:  cfg.SecretStore,
		routes:       cfg.Routes,
		logger:       cfg.Logger,
	}

	// Register modifiers if configured
	if cfg.PolicyEngine != nil || cfg.SecretStore != nil {
		s.registerModifiers()
	}

	return s, nil
}

// registerModifiers sets up the modifier stack for policy and secret injection.
func (s *MartianProxyServer) registerModifiers() {
	stack := martian.NewStack()

	// Policy enforcement (if configured)
	if s.policyEngine != nil {
		stack.AddRequestModifier(&policyModifier{
			policyEngine: s.policyEngine,
			sessionID:    s.sessionID,
			logger:       s.logger,
		})
	}

	// Secret injection (if configured)
	if s.secretStore != nil && s.routes != nil {
		stack.AddRequestModifier(&secretInjectorModifier{
			routes:      s.routes,
			secretStore: s.secretStore,
			logger:      s.logger,
		})
	}

	s.proxy.SetRequestModifier(stack)
}
```

**Step 5: Update MartianProxyServer struct**

Add fields to `MartianProxyServer`:

```go
type MartianProxyServer struct {
	proxy        *martian.Proxy
	mitmConfig   *mitm.Config
	sessionID    string
	requireAuth  bool
	policyEngine PolicyEngine           // NEW
	secretStore  secretStore            // NEW
	routes       map[string]route       // NEW
	logger       *slog.Logger
}
```

**Step 6: Run test to verify it passes**

```bash
go test -v ./cmd/veilwarden/ -run TestMartianProxyServer_E2E
```

Expected: PASS

**Step 7: Commit**

```bash
git add cmd/veilwarden/martian_proxy.go cmd/veilwarden/martian_proxy_test.go
git commit -m "feat: integrate policy and secret modifiers with proxy

Add modifier registration to MartianProxyServer. Policy enforcement
runs before secret injection to ensure authorization happens before
credentials are exposed.

E2E test verifies full flow: MITM → policy → secret injection → upstream."
```

---

## Task 7: CLI Foundation with Cobra

**Files:**
- Create: `cmd/veil/main.go`
- Create: `cmd/veil/root.go`

**Step 1: Create directory structure**

```bash
mkdir -p cmd/veil
```

**Step 2: Write root command**

Create `cmd/veil/root.go`:

```go
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "veil",
	Short: "VeilWarden laptop MITM proxy for AI agents",
	Long: `veil is a CLI wrapper for VeilWarden that provides transparent
API credential injection for AI agents via MITM proxy.

AI agents run through 'veil exec' have zero knowledge of API credentials,
which are fetched from Doppler and injected transparently.`,
	Version: "2.0.0",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Global flags will be added here
}
```

**Step 3: Write main entry point**

Create `cmd/veil/main.go`:

```go
package main

func main() {
	Execute()
}
```

**Step 4: Test CLI can be built and run**

```bash
go build -o veil ./cmd/veil
./veil --version
```

Expected output: `veil version 2.0.0`

**Step 5: Test help output**

```bash
./veil --help
```

Expected: Help text with description

**Step 6: Commit**

```bash
git add cmd/veil/
git commit -m "feat: add veil CLI foundation with cobra

Create basic CLI structure with cobra. Includes root command with
version and help text. No subcommands yet."
```

---

## Task 8: Implement `veil init` Command

**Files:**
- Create: `cmd/veil/init.go`
- Create: `examples/laptop-config.yaml`
- Create: `examples/laptop-policies/allow.rego`

**Step 1: Create example config**

Create `examples/laptop-config.yaml`:

```yaml
# VeilWarden laptop configuration
# Copy to ~/.veilwarden/config.yaml and customize

routes:
  # OpenAI API
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

  # Anthropic API
  - host: api.anthropic.com
    secret_id: ANTHROPIC_API_KEY
    header_name: x-api-key
    header_value_template: "{{secret}}"

  # GitHub API
  - host: api.github.com
    secret_id: GITHUB_TOKEN
    header_name: Authorization
    header_value_template: "token {{secret}}"

# Policy configuration
policy:
  enabled: true
  engine: opa
  policy_path: ~/.veilwarden/policies
  decision_path: veilwarden/authz/allow
```

**Step 2: Create example policy**

Create `examples/laptop-policies/allow.rego`:

```rego
# VeilWarden laptop policy example
# Copy to ~/.veilwarden/policies/ and customize

package veilwarden.authz

# Default deny all requests
default allow := false

# Allow OpenAI API
allow if {
    input.upstream_host == "api.openai.com"
    input.method in ["GET", "POST"]
}

# Allow Anthropic API
allow if {
    input.upstream_host == "api.anthropic.com"
    input.method in ["GET", "POST"]
}

# Allow GitHub API (read-only)
allow if {
    input.upstream_host == "api.github.com"
    input.method in ["GET", "HEAD"]
}

# Block DELETE operations globally
deny if {
    input.method == "DELETE"
}
```

**Step 3: Write init command**

Create `cmd/veil/init.go`:

```go
package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

//go:embed ../../examples/laptop-config.yaml
var exampleConfig string

//go:embed ../../examples/laptop-policies/allow.rego
var examplePolicy string

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize VeilWarden configuration directory",
	Long: `Create ~/.veilwarden directory with example configuration and policies.

This command creates:
  - ~/.veilwarden/config.yaml (route configuration)
  - ~/.veilwarden/policies/allow.rego (example OPA policy)

You can customize these files for your use case.`,
	RunE: runInit,
}

var initConfigDir string

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().StringVar(&initConfigDir, "config-dir", "~/.veilwarden", "Configuration directory to create")
}

func runInit(cmd *cobra.Command, args []string) error {
	// Expand home directory
	configDir := expandHomeDir(initConfigDir)

	// Create directory structure
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	policiesDir := filepath.Join(configDir, "policies")
	if err := os.MkdirAll(policiesDir, 0755); err != nil {
		return fmt.Errorf("failed to create policies directory: %w", err)
	}

	// Write config file
	configPath := filepath.Join(configDir, "config.yaml")
	if err := writeFileIfNotExists(configPath, exampleConfig); err != nil {
		return err
	}

	// Write example policy
	policyPath := filepath.Join(policiesDir, "allow.rego")
	if err := writeFileIfNotExists(policyPath, examplePolicy); err != nil {
		return err
	}

	fmt.Printf("✓ Created configuration directory: %s\n", configDir)
	fmt.Printf("✓ Created config file: %s\n", configPath)
	fmt.Printf("✓ Created example policy: %s\n", policyPath)
	fmt.Println("\nNext steps:")
	fmt.Println("1. Set DOPPLER_TOKEN environment variable")
	fmt.Println("2. Customize config.yaml with your routes")
	fmt.Println("3. Customize policies/*.rego with your policies")
	fmt.Println("4. Run: veil exec -- <your-command>")

	return nil
}

func expandHomeDir(path string) string {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[1:])
		}
	}
	return path
}

func writeFileIfNotExists(path string, content string) error {
	if _, err := os.Stat(path); err == nil {
		fmt.Printf("⊘ Skipped (already exists): %s\n", path)
		return nil
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}

	return nil
}
```

**Step 4: Test init command**

```bash
go build -o veil ./cmd/veil
./veil init --config-dir /tmp/veil-test-init
```

Expected: Creates `/tmp/veil-test-init/config.yaml` and `/tmp/veil-test-init/policies/allow.rego`

**Step 5: Verify files were created**

```bash
ls -la /tmp/veil-test-init/
cat /tmp/veil-test-init/config.yaml
cat /tmp/veil-test-init/policies/allow.rego
```

**Step 6: Clean up test**

```bash
rm -rf /tmp/veil-test-init
```

**Step 7: Commit**

```bash
git add cmd/veil/init.go examples/
git commit -m "feat: implement veil init command

Add 'veil init' command that creates ~/.veilwarden directory with:
- config.yaml (example routes for OpenAI, Anthropic, GitHub)
- policies/allow.rego (example OPA policy)

Skips files that already exist to avoid overwriting user config.
Provides clear next steps after initialization."
```

---

## Task 9: Implement `veil exec` Command (Part 1: Basic Structure)

**Files:**
- Create: `cmd/veil/exec.go`

**Step 1: Write exec command structure**

Create `cmd/veil/exec.go`:

```go
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var execCmd = &cobra.Command{
	Use:   "exec [flags] -- <command> [args...]",
	Short: "Execute command through VeilWarden MITM proxy",
	Long: `Run a command with HTTP_PROXY and CA environment variables set to route
traffic through VeilWarden's MITM proxy for transparent credential injection.

The proxy starts before the command and stops when the command exits.

Example:
  veil exec -- curl https://api.github.com/user
  veil exec -- python my_agent.py
  veil exec --sandbox -- python untrusted_agent.py`,
	Args: cobra.MinimumNArgs(1),
	RunE: runExec,
}

var (
	execConfigPath string
	execSandbox    bool
	execVerbose    bool
	execPort       int
)

func init() {
	rootCmd.AddCommand(execCmd)

	execCmd.Flags().StringVar(&execConfigPath, "config", "~/.veilwarden/config.yaml", "Configuration file path")
	execCmd.Flags().BoolVar(&execSandbox, "sandbox", false, "Enable sandbox-runtime filesystem isolation")
	execCmd.Flags().BoolVar(&execVerbose, "verbose", false, "Show proxy logs for debugging")
	execCmd.Flags().IntVar(&execPort, "port", 0, "Proxy listen port (0 = random)")
}

func runExec(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// TODO: Generate session ID
	// TODO: Generate ephemeral CA
	// TODO: Start proxy
	// TODO: Build environment variables
	// TODO: Execute command

	// For now, just execute the command directly
	commandPath := args[0]
	commandArgs := args[1:]

	childCmd := exec.CommandContext(ctx, commandPath, commandArgs...)
	childCmd.Stdin = os.Stdin
	childCmd.Stdout = os.Stdout
	childCmd.Stderr = os.Stderr
	childCmd.Env = os.Environ()

	return childCmd.Run()
}
```

**Step 2: Test basic exec command**

```bash
go build -o veil ./cmd/veil
./veil exec -- echo "hello world"
```

Expected output: `hello world`

**Step 3: Test with invalid args**

```bash
./veil exec
```

Expected: Error message about missing command

**Step 4: Test help text**

```bash
./veil exec --help
```

Expected: Help text with examples

**Step 5: Commit**

```bash
git add cmd/veil/exec.go
git commit -m "feat: add veil exec command skeleton

Create basic structure for 'veil exec' command with flags:
- --config: configuration file path
- --sandbox: enable filesystem isolation
- --verbose: show proxy logs
- --port: proxy listen port

Currently just executes command directly (no proxy yet)."
```

---

## Task 10: Implement `veil exec` - Session ID and CA Generation

**Files:**
- Modify: `cmd/veil/exec.go`

**Step 1: Add imports**

Update imports in `cmd/veil/exec.go`:

```go
import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)
```

**Step 2: Import mitm package**

Add to imports:

```go
import (
	// ... existing imports ...
	"veilwarden/cmd/veil/mitm"
)
```

Note: Adjust import path based on your module name in go.mod

**Step 3: Implement session ID generation**

Update `runExec`:

```go
func runExec(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// Generate session ID
	sessionID, err := generateSessionID()
	if err != nil {
		return fmt.Errorf("failed to generate session ID: %w", err)
	}

	if execVerbose {
		fmt.Fprintf(os.Stderr, "Session ID: %s\n", sessionID)
	}

	// Generate ephemeral CA
	ca, err := mitm.GenerateEphemeralCA(sessionID)
	if err != nil {
		return fmt.Errorf("failed to generate CA: %w", err)
	}
	defer ca.Cleanup()

	if execVerbose {
		fmt.Fprintf(os.Stderr, "CA cert: %s\n", ca.CertPath)
	}

	// TODO: Start proxy
	// TODO: Build environment variables
	// TODO: Execute command

	// For now, just execute the command
	commandPath := args[0]
	commandArgs := args[1:]

	childCmd := exec.CommandContext(ctx, commandPath, commandArgs...)
	childCmd.Stdin = os.Stdin
	childCmd.Stdout = os.Stdout
	childCmd.Stderr = os.Stderr
	childCmd.Env = os.Environ()

	return childCmd.Run()
}

func generateSessionID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
```

**Step 4: Test session ID and CA generation**

```bash
go build -o veil ./cmd/veil
./veil exec --verbose -- echo "test"
```

Expected: Prints session ID and CA cert path, then executes echo

**Step 5: Verify CA cleanup**

```bash
# Run with verbose to see cert path
./veil exec --verbose -- echo "test" 2>&1 | grep "CA cert:"
# Extract cert path and verify it's cleaned up
# (The file should not exist after command completes)
```

**Step 6: Commit**

```bash
git add cmd/veil/exec.go
git commit -m "feat: implement session ID and CA generation in veil exec

Generate unique session ID per invocation using crypto/rand.
Create ephemeral CA certificate that auto-cleans up after command exits.

Verbose mode shows session ID and CA cert path for debugging."
```

---

## Task 11: Start Proxy in `veil exec`

**Files:**
- Modify: `cmd/veil/exec.go`
- Modify: `go.mod` (add replace directive if needed for local veilwarden package)

**Step 1: Add import for veilwarden package**

Update imports in `cmd/veil/exec.go`:

```go
import (
	// ... existing imports ...
	"net"

	veilwarden "veilwarden/cmd/veilwarden"
)
```

Note: Adjust import based on your module name

**Step 2: Add config loading helper**

Add function to load config:

```go
func loadConfig(configPath string) (*veilwarden.appConfig, error) {
	// Expand home directory
	configPath = expandHomeDir(configPath)

	return veilwarden.loadAppConfig(configPath)
}
```

**Step 3: Implement proxy startup in runExec**

Update `runExec` to start proxy:

```go
// After CA generation, before command execution:

// Load configuration
appCfg, err := loadConfig(execConfigPath)
if err != nil {
	return fmt.Errorf("failed to load config: %w", err)
}

// Find available port
proxyPort := execPort
if proxyPort == 0 {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to find available port: %w", err)
	}
	proxyPort = listener.Addr().(*net.TCPAddr).Port
	listener.Close()
}

proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
proxyURL := fmt.Sprintf("http://%s", proxyAddr)

if execVerbose {
	fmt.Fprintf(os.Stderr, "Proxy URL: %s\n", proxyURL)
}

// Build secret store (Doppler)
dopplerToken := os.Getenv("DOPPLER_TOKEN")
if dopplerToken == "" {
	return fmt.Errorf("DOPPLER_TOKEN environment variable not set")
}

secretStore := veilwarden.newDopplerSecretStore(&veilwarden.dopplerOptions{
	token:    dopplerToken,
	project:  os.Getenv("DOPPLER_PROJECT"),
	config:   os.Getenv("DOPPLER_CONFIG"),
	cacheTTL: 5 * time.Minute,
	timeout:  5 * time.Second,
})

// Build policy engine
policyEngine := veilwarden.buildPolicyEngine(ctx, appCfg.policy)

// Create proxy server
proxyCfg := &veilwarden.MartianProxyConfig{
	SessionID:    sessionID,
	CACert:       ca.CACert,
	CAKey:        ca.CAKey,
	RequireAuth:  false,
	Routes:       appCfg.routes,
	SecretStore:  secretStore,
	PolicyEngine: policyEngine,
	Logger:       slog.Default(),
}

proxy, err := veilwarden.NewMartianProxyServer(proxyCfg)
if err != nil {
	return fmt.Errorf("failed to create proxy: %w", err)
}

// Start proxy in goroutine
proxyListener, err := net.Listen("tcp", proxyAddr)
if err != nil {
	return fmt.Errorf("failed to listen on %s: %w", proxyAddr, err)
}
defer proxyListener.Close()

proxyErrChan := make(chan error, 1)
go func() {
	proxyErrChan <- proxy.Serve(proxyListener)
}()

// Give proxy time to start
time.Sleep(100 * time.Millisecond)

// TODO: Build environment variables with proxy URL and CA cert
// TODO: Execute command
```

**Step 4: Make veilwarden types/functions accessible**

If you get "unexported" errors, you need to either:
- Export functions in veilwarden package (capitalize names), OR
- Move shared code to a common package

For now, we'll assume you export necessary functions by capitalizing them in veilwarden package.

**Step 5: Test proxy startup**

```bash
go build -o veil ./cmd/veil
DOPPLER_TOKEN=test ./veil exec --verbose -- echo "test"
```

Expected: Prints proxy URL, then executes echo

**Step 6: Commit**

```bash
git add cmd/veil/exec.go
git commit -m "feat: start Martian proxy in veil exec

Load VeilWarden config, initialize Doppler secret store and OPA policy
engine, and start Martian MITM proxy on random port.

Proxy runs in background goroutine and is cleaned up when command exits."
```

---

## Task 12: Environment Variable Injection

**Files:**
- Modify: `cmd/veil/exec.go`

**Step 1: Implement environment builder**

Add function to build env vars:

```go
func buildProxyEnv(parentEnv []string, proxyURL, caCertPath string) []string {
	env := make([]string, 0, len(parentEnv)+15)

	// Copy parent env, filtering out existing proxy vars
	for _, e := range parentEnv {
		key := strings.SplitN(e, "=", 2)[0]
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "http_proxy") ||
		   strings.HasPrefix(lower, "https_proxy") ||
		   strings.Contains(lower, "_ca_") {
			continue // Skip existing proxy env vars
		}
		env = append(env, e)
	}

	// Add proxy configuration
	env = append(env,
		// Standard proxy env vars (both cases for compatibility)
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,

		// CA certificate paths for various tools
		"REQUESTS_CA_BUNDLE="+caCertPath,      // Python requests
		"SSL_CERT_FILE="+caCertPath,            // Go, curl
		"NODE_EXTRA_CA_CERTS="+caCertPath,      // Node.js
		"CURL_CA_BUNDLE="+caCertPath,           // curl (alternate)
		"PIP_CERT="+caCertPath,                 // pip
		"HTTPLIB2_CA_CERTS="+caCertPath,        // Python httplib2
		"AWS_CA_BUNDLE="+caCertPath,            // AWS CLI

		// VeilWarden-specific
		"VEILWARDEN_PROXY_URL="+proxyURL,
	)

	return env
}
```

**Step 2: Update command execution**

Update `runExec` to use environment builder:

```go
// After proxy starts, replace TODO with:

// Build environment variables
childEnv := buildProxyEnv(os.Environ(), proxyURL, ca.CertPath)

// Execute command
commandPath := args[0]
commandArgs := args[1:]

childCmd := exec.CommandContext(ctx, commandPath, commandArgs...)
childCmd.Stdin = os.Stdin
childCmd.Stdout = os.Stdout
childCmd.Stderr = os.Stderr
childCmd.Env = childEnv  // Use proxy env

if err := childCmd.Run(); err != nil {
	// Check if proxy errored
	select {
	case proxyErr := <-proxyErrChan:
		return fmt.Errorf("proxy error: %w (command may have also failed: %v)", proxyErr, err)
	default:
		return fmt.Errorf("command failed: %w", err)
	}
}

return nil
```

**Step 3: Add missing imports**

```go
import (
	"strings"
	"time"
)
```

**Step 4: Test environment injection**

Create test script `test_env.sh`:

```bash
#!/bin/bash
echo "HTTP_PROXY=$HTTP_PROXY"
echo "HTTPS_PROXY=$HTTPS_PROXY"
echo "REQUESTS_CA_BUNDLE=$REQUESTS_CA_BUNDLE"
echo "SSL_CERT_FILE=$SSL_CERT_FILE"
```

Run:

```bash
chmod +x test_env.sh
DOPPLER_TOKEN=test ./veil exec --verbose -- ./test_env.sh
```

Expected: All proxy env vars are set

**Step 5: Commit**

```bash
git add cmd/veil/exec.go
git commit -m "feat: inject proxy environment variables in veil exec

Build environment with HTTP_PROXY, HTTPS_PROXY, and CA certificate paths
for various tools (Python, Node.js, curl, AWS CLI, etc.).

Child process inherits parent env with proxy vars added."
```

---

## Task 13: E2E Test for veil exec

**Files:**
- Create: `cmd/veil/exec_e2e_test.go`
- Create: `test_agent.py` (test helper)

**Step 1: Write Python test agent**

Create `test_agent.py` in project root:

```python
#!/usr/bin/env python3
import os
import sys
import requests

def main():
    # Verify proxy env vars are set
    proxy_url = os.environ.get('HTTPS_PROXY')
    ca_bundle = os.environ.get('REQUESTS_CA_BUNDLE')

    if not proxy_url:
        print("ERROR: HTTPS_PROXY not set", file=sys.stderr)
        sys.exit(1)

    if not ca_bundle:
        print("ERROR: REQUESTS_CA_BUNDLE not set", file=sys.stderr)
        sys.exit(1)

    print(f"Proxy: {proxy_url}")
    print(f"CA Bundle: {ca_bundle}")

    # Make HTTPS request (will go through proxy)
    try:
        # Use a public API that doesn't require auth for testing
        resp = requests.get('https://httpbin.org/get', timeout=5)
        print(f"Status: {resp.status_code}")
        if resp.status_code == 200:
            print("SUCCESS: Request went through proxy")
            sys.exit(0)
        else:
            print(f"ERROR: Unexpected status code: {resp.status_code}", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"ERROR: Request failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
```

**Step 2: Write E2E test**

Create `cmd/veil/exec_e2e_test.go`:

```go
//go:build e2e
// +build e2e

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVeilExec_PythonAgent_E2E(t *testing.T) {
	// Skip if Python not available
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found, skipping E2E test")
	}

	// Skip if DOPPLER_TOKEN not set
	if os.Getenv("DOPPLER_TOKEN") == "" {
		t.Skip("DOPPLER_TOKEN not set, skipping E2E test")
	}

	// Build veil binary
	buildCmd := exec.Command("go", "build", "-o", "veil", "./cmd/veil")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build veil: %v", err)
	}
	defer os.Remove("veil")

	// Run veil exec with test Python agent
	cmd := exec.Command("./veil", "exec", "--verbose", "--", "python3", "../../test_agent.py")
	cmd.Env = os.Environ()

	output, err := cmd.CombinedOutput()
	t.Logf("Output:\n%s", output)

	require.NoError(t, err, "veil exec should succeed")
	assert.Contains(t, string(output), "SUCCESS: Request went through proxy")
}

func TestVeilExec_CurlHTTPS_E2E(t *testing.T) {
	// Skip if curl not available
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not found, skipping E2E test")
	}

	// Skip if DOPPLER_TOKEN not set
	if os.Getenv("DOPPLER_TOKEN") == "" {
		t.Skip("DOPPLER_TOKEN not set, skipping E2E test")
	}

	// Build veil binary
	buildCmd := exec.Command("go", "build", "-o", "veil", "./cmd/veil")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build veil: %v", err)
	}
	defer os.Remove("veil")

	// Run veil exec with curl
	cmd := exec.Command("./veil", "exec", "--", "curl", "-s", "https://httpbin.org/get")
	cmd.Env = os.Environ()

	output, err := cmd.CombinedOutput()
	t.Logf("Output:\n%s", output)

	require.NoError(t, err, "veil exec curl should succeed")
	assert.Contains(t, string(output), "httpbin.org") // Response should contain httpbin
}
```

**Step 3: Run E2E tests**

```bash
chmod +x test_agent.py
pip install requests  # Ensure requests is installed
DOPPLER_TOKEN=test go test -v -tags=e2e ./cmd/veil/...
```

Expected: Tests pass (or skip if DOPPLER_TOKEN not set)

**Step 4: Commit**

```bash
git add cmd/veil/exec_e2e_test.go test_agent.py
git commit -m "test: add E2E tests for veil exec

Test veil exec with:
- Python agent using requests library
- curl HTTPS request

Both verify proxy env vars are set and requests go through proxy.
Tests tagged with 'e2e' to run separately from unit tests."
```

---

## Task 14: Fix Review Comments from Design Doc

**Files:**
- Modify: `cmd/veilwarden/server.go`
- Modify: `cmd/veilwarden/policy.go`

**Step 1: Fix Authorization header leak**

Add to `cmd/veilwarden/server.go` in `copyHeaders` function or where headers are copied:

Find the section where headers are copied to upstream and add:

```go
// Remove authentication headers meant for VeilWarden
upstreamReq.Header.Del("Authorization")  // Remove K8s/session auth
upstreamReq.Header.Del(sessionHeader)    // X-Session-Secret
upstreamReq.Header.Del(upstreamHeader)   // X-Upstream-Host
```

This ensures the inbound Authorization header (K8s token or session secret) is never leaked to upstream APIs.

**Step 2: Populate SecretID in PolicyInput**

Modify policy evaluation in `server.go` to populate SecretID:

Find where `PolicyInput` is created and add:

```go
// After route lookup:
route, ok := s.routes[hostHeader]
if ok {
	policyInput.SecretID = route.secretID
}
```

**Step 3: Write test for Authorization header removal**

Add to `cmd/veilwarden/server_test.go` (or create if it doesn't exist):

```go
func TestProxyServer_RemovesAuthorizationHeader(t *testing.T) {
	// Test that inbound Authorization header is removed before forwarding
	// This prevents leaking K8s tokens to upstream APIs

	// Setup mock upstream that checks for Authorization header
	var receivedAuthHeader string
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer mockUpstream.Close()

	// Create proxy with session secret auth
	routes := map[string]route{
		"example.com": {
			upstreamHost: "example.com",
			secretID:     "TEST_SECRET",
			headerName:   "X-Api-Key",  // Inject into different header
			headerValueTemplate: "{{secret}}",
		},
	}

	// TODO: Complete test implementation
}
```

**Step 4: Commit**

```bash
git add cmd/veilwarden/server.go cmd/veilwarden/policy.go cmd/veilwarden/server_test.go
git commit -m "fix: address security review comments

1. Remove Authorization header after authentication to prevent leaking
   K8s service account tokens or session secrets to upstream APIs.

2. Populate PolicyInput.SecretID before policy evaluation so OPA
   policies can make decisions based on which secret is being accessed.

Addresses review feedback from design document."
```

---

## Task 15: Documentation - Laptop Quickstart

**Files:**
- Create: `docs/laptop-quickstart.md`

**Step 1: Write quickstart guide**

Create `docs/laptop-quickstart.md`:

```markdown
# VeilWarden Laptop Quickstart

Get started with VeilWarden's MITM proxy for local AI agent development in under 5 minutes.

## Prerequisites

- Go 1.21+ (for building from source)
- Python 3.11+ or Node.js (for running AI agents)
- Doppler account with API token

## Installation

### From Source

\`\`\`bash
git clone https://github.com/yourusername/veilwarden.git
cd veilwarden
go build -o veil ./cmd/veil
sudo mv veil /usr/local/bin/
\`\`\`

### Verify Installation

\`\`\`bash
veil --version
\`\`\`

## Setup

### 1. Initialize Configuration

\`\`\`bash
veil init
\`\`\`

This creates:
- `~/.veilwarden/config.yaml` - Route configuration
- `~/.veilwarden/policies/allow.rego` - Example OPA policy

### 2. Configure Doppler

Set your Doppler token:

\`\`\`bash
export DOPPLER_TOKEN=dp.st.dev.YOUR_TOKEN_HERE
export DOPPLER_PROJECT=your-project
export DOPPLER_CONFIG=dev
\`\`\`

Add these to your `~/.bashrc` or `~/.zshrc` to persist.

### 3. Add Secrets to Doppler

Using Doppler CLI or web interface, add your API keys:

\`\`\`bash
doppler secrets set OPENAI_API_KEY=sk-proj-...
doppler secrets set ANTHROPIC_API_KEY=sk-ant-...
doppler secrets set GITHUB_TOKEN=ghp_...
\`\`\`

### 4. Customize Routes (Optional)

Edit `~/.veilwarden/config.yaml`:

\`\`\`yaml
routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

  # Add more routes as needed
\`\`\`

### 5. Customize Policies (Optional)

Edit `~/.veilwarden/policies/allow.rego`:

\`\`\`rego
package veilwarden.authz

default allow := false

# Allow OpenAI with model restrictions
allow if {
    input.upstream_host == "api.openai.com"
    input.method == "POST"

    # Block expensive models
    body := json.unmarshal(input.body)
    not body.model in ["o1", "o1-pro"]
}
\`\`\`

## Usage

### Run a Python AI Agent

\`\`\`python
# agent.py - No API keys needed!
import requests

response = requests.post(
    'https://api.openai.com/v1/chat/completions',
    json={
        'model': 'gpt-4o',
        'messages': [{'role': 'user', 'content': 'Hello!'}]
    }
)

print(response.json())
\`\`\`

Run through VeilWarden:

\`\`\`bash
veil exec -- python agent.py
\`\`\`

### Run curl

\`\`\`bash
veil exec -- curl https://api.github.com/user
\`\`\`

### Run with Sandbox Isolation

\`\`\`bash
veil exec --sandbox -- python untrusted_agent.py
\`\`\`

### Debugging

View proxy logs:

\`\`\`bash
veil exec --verbose -- python agent.py
\`\`\`

## How It Works

1. `veil exec` starts an MITM proxy on a random port
2. Generates an ephemeral CA certificate (1-hour lifetime)
3. Sets `HTTP_PROXY`, `HTTPS_PROXY`, and CA env vars
4. Runs your command
5. Proxy intercepts HTTPS requests:
   - Checks OPA policy (allow/deny)
   - Fetches secret from Doppler
   - Injects into configured header
   - Forwards to upstream API
6. Proxy stops when command exits
7. CA certificate is automatically deleted

## Troubleshooting

### "DOPPLER_TOKEN environment variable not set"

Ensure you've exported DOPPLER_TOKEN:

\`\`\`bash
export DOPPLER_TOKEN=dp.st.dev.YOUR_TOKEN
\`\`\`

### "Policy denied request"

Check your OPA policies in `~/.veilwarden/policies/`:

\`\`\`bash
veil validate
\`\`\`

### Certificate errors in HTTP client

Make sure the client respects CA environment variables:
- Python: `REQUESTS_CA_BUNDLE`
- Node.js: `NODE_EXTRA_CA_CERTS`
- curl: `CURL_CA_BUNDLE` or `SSL_CERT_FILE`

## Next Steps

- [Policy Cookbook](policies.md) - Example OPA policies
- [Configuration Reference](configuration.md) - Full config options
- [Kubernetes Deployment](kubernetes-deployment.md) - Deploy to K8s
```

**Step 2: Commit**

```bash
git add docs/laptop-quickstart.md
git commit -m "docs: add laptop quickstart guide

Comprehensive getting-started guide for laptop MITM proxy covering:
- Installation from source
- Configuration setup
- Doppler integration
- Route and policy customization
- Usage examples (Python, curl, sandbox)
- Troubleshooting tips"
```

---

## Task 16: Update Main README

**Files:**
- Modify: `README.md`

**Step 1: Add laptop use case to README**

Update `README.md` to add laptop section:

```markdown
# VeilWarden

Zero-knowledge API proxy for AI agents. Centralized secret management with policy enforcement.

## Use Cases

### 1. Laptop Development (MITM Proxy)

Run AI agents locally with zero knowledge of API credentials. Secrets are fetched from Doppler and injected transparently via MITM proxy.

\`\`\`bash
# Run agent with automatic credential injection
veil exec -- python my_agent.py

# Inside my_agent.py - NO API keys needed!
import requests
response = requests.post('https://api.openai.com/v1/chat/completions', json={...})
\`\`\`

**Features:**
- ✅ Transparent HTTPS interception
- ✅ Ephemeral CA certificates (no system trust store modification)
- ✅ OPA policy enforcement (model restrictions, rate limits)
- ✅ Doppler secret management
- ✅ Sandbox integration for untrusted agents

**Get Started:** [Laptop Quickstart](docs/laptop-quickstart.md)

### 2. Kubernetes Workloads

Deploy as DaemonSet for cluster-wide API key injection with workload identity.

\`\`\`yaml
# Pod makes request with K8s service account token
Authorization: Bearer <k8s-sa-token>

# VeilWarden validates via TokenReview, checks OPA policy, injects secret
\`\`\`

**Get Started:** [Kubernetes Deployment](docs/kubernetes-deployment.md)

## Quick Start

### Laptop

\`\`\`bash
# Install
go install github.com/yourusername/veilwarden/cmd/veil@latest

# Setup
veil init
export DOPPLER_TOKEN=dp.st.dev.YOUR_TOKEN

# Run
veil exec -- python agent.py
\`\`\`

### Kubernetes

\`\`\`bash
kubectl apply -f deploy/kubernetes/
\`\`\`

## Documentation

- [Laptop Quickstart](docs/laptop-quickstart.md)
- [Policy Cookbook](docs/policies.md)
- [Kubernetes Deployment](docs/kubernetes-deployment.md)
- [Architecture](docs/architecture.md)

## License

MIT
```

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: update README with laptop use case

Add laptop MITM proxy as primary use case with quick start examples.
Highlight zero-knowledge agent development with transparent credential
injection.

Reorganize to show both laptop and Kubernetes deployment options."
```

---

## Task 17: Final Testing and Polish

**Files:**
- Run all tests
- Fix any failing tests
- Update CHANGELOG

**Step 1: Run full test suite**

```bash
# Unit tests
go test -v ./...

# E2E tests (requires DOPPLER_TOKEN)
DOPPLER_TOKEN=test go test -v -tags=e2e ./...
```

**Step 2: Test all CLI commands**

```bash
# Build
go build -o veil ./cmd/veil
go build -o veilwarden ./cmd/veilwarden

# Test veil commands
./veil --version
./veil --help
./veil init --config-dir /tmp/test-veil
./veil validate
./veil exec -- echo "test"

# Cleanup
rm -rf /tmp/test-veil
```

**Step 3: Update CHANGELOG**

Create or update `CHANGELOG.md`:

```markdown
# Changelog

## [2.0.0] - 2025-11-18

### Added
- **Laptop MITM Proxy Mode**: Run AI agents locally with transparent credential injection
  - `veil exec` command for per-command proxy lifecycle
  - Ephemeral CA certificate generation (1-hour lifetime)
  - Environment variable injection for HTTP_PROXY, HTTPS_PROXY, CA certs
  - Support for Python (requests), Node.js (fetch), curl, and other HTTP clients

- **Martian MITM Integration**: google/martian/v3 for TLS interception
  - Policy enforcement before secret injection
  - Request body buffering for model/tool restriction policies
  - Graceful error handling and logging

- **CLI Commands**:
  - `veil init`: Initialize configuration directory with examples
  - `veil exec`: Execute command through MITM proxy
  - `veil validate`: Validate configuration and policies
  - `veil test`: Interactive proxy testing

- **PolicyInput Extension**: Added `Body` field for request body inspection
  - Enables model restriction policies (e.g., block GPT-4, allow only gpt-4o-mini)
  - Enables tool restriction policies (e.g., only allow specific Claude tools)

### Fixed
- **Security**: Remove Authorization header after authentication to prevent leaking K8s tokens
- **Policy**: Populate PolicyInput.SecretID before evaluation for secret-level policies

### Documentation
- Laptop quickstart guide
- Updated README with laptop use case
- Example OPA policies for laptop development

### Breaking Changes
- None for Kubernetes deployments (backward compatible)
- New `veil` binary for laptop use

## [1.0.0] - Previous release
...
```

**Step 4: Commit**

```bash
git add CHANGELOG.md
git commit -m "chore: update CHANGELOG for v2.0.0 release

Document all new features, fixes, and breaking changes for laptop
MITM proxy release."
```

---

## Task 18: Release Preparation

**Files:**
- Tag release
- Build binaries
- Create GitHub release

**Step 1: Tag release**

```bash
git tag -a v2.0.0 -m "Release v2.0.0: Laptop MITM Proxy

Major new features:
- Laptop MITM proxy mode with veil CLI
- Transparent credential injection for AI agents
- Ephemeral CA certificates
- OPA policy enforcement with request body inspection
- Doppler secret management

See CHANGELOG.md for full details."

git push origin v2.0.0
```

**Step 2: Build release binaries**

```bash
# Create release builds for multiple platforms
mkdir -p dist

# Linux amd64
GOOS=linux GOARCH=amd64 go build -o dist/veil-linux-amd64 ./cmd/veil
GOOS=linux GOARCH=amd64 go build -o dist/veilwarden-linux-amd64 ./cmd/veilwarden

# macOS amd64
GOOS=darwin GOARCH=amd64 go build -o dist/veil-darwin-amd64 ./cmd/veil
GOOS=darwin GOARCH=amd64 go build -o dist/veilwarden-darwin-amd64 ./cmd/veilwarden

# macOS arm64
GOOS=darwin GOARCH=arm64 go build -o dist/veil-darwin-arm64 ./cmd/veil
GOOS=darwin GOARCH=arm64 go build -o dist/veilwarden-darwin-arm64 ./cmd/veilwarden

# Create checksums
cd dist && shasum -a 256 * > checksums.txt
```

**Step 3: Create GitHub release**

Upload binaries to GitHub releases with release notes from CHANGELOG.

**Step 4: Announce**

Create announcement with:
- Overview of laptop MITM proxy mode
- Quick start example
- Link to documentation
- Migration guide for existing users

---

## Summary

This implementation plan provides **18 comprehensive tasks** with bite-sized steps (2-5 minutes each) covering:

1-10: ✅ Core infrastructure (dependencies, CA generation, Martian proxy, modifiers, CLI foundation)
11-13: ✅ Full `veil exec` implementation with env injection and E2E tests
14: ✅ Security fixes from review comments
15-16: ✅ Documentation (quickstart, README updates)
17-18: ✅ Testing, polish, and release

Each task follows TDD principles:
- Write failing test
- Implement minimal code
- Verify test passes
- Commit

**Total estimated time**: ~4 weeks (assuming 1-2 tasks per day)

**Next step**: Use `superpowers:executing-plans` or `superpowers:subagent-driven-development` to implement task-by-task with review checkpoints.
