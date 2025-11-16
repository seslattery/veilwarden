# Kubernetes Workload Identity - Implementation Plan

## Overview

This document provides a detailed implementation plan for adding Kubernetes Service Account token authentication to veilwarden. This plan breaks down the work into milestones with clear deliverables, file changes, and verification steps.

**Related Documents:**
- Design: `docs/kubernetes-workload-identity.md`
- Example Policies: `policies/kubernetes-example.rego`

## Dependencies to Add

```bash
go get k8s.io/api@v0.31.0
go get k8s.io/apimachinery@v0.31.0
go get k8s.io/client-go@v0.31.0
go get sigs.k8s.io/controller-runtime@v0.19.0  # For EnvTest
```

**Update `go.mod`:**
```go
require (
    k8s.io/api v0.31.0
    k8s.io/apimachinery v0.31.0
    k8s.io/client-go v0.31.0
    sigs.k8s.io/controller-runtime v0.19.0  // For testing
)
```

---

## Milestone 1: Core Token Validation

**Goal:** Implement Kubernetes Service Account token validation using TokenReview API.

### New Files

#### `cmd/veilwarden/k8s_client.go`

Kubernetes API client wrapper for TokenReview.

```go
package main

import (
    "context"
    "fmt"
    "os"
    "path/filepath"

    authv1 "k8s.io/api/authentication/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
    "k8s.io/client-go/tools/clientcmd"
)

type k8sClient struct {
    clientset kubernetes.Interface
}

// newK8sClient creates a Kubernetes client for TokenReview API calls.
// In-cluster config is attempted first, falling back to kubeconfig for local development.
func newK8sClient() (*k8sClient, error) {
    config, err := rest.InClusterConfig()
    if err != nil {
        // Fallback to kubeconfig for local development
        kubeconfig := os.Getenv("KUBECONFIG")
        if kubeconfig == "" {
            home, _ := os.UserHomeDir()
            kubeconfig = filepath.Join(home, ".kube", "config")
        }
        config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
        if err != nil {
            return nil, fmt.Errorf("failed to build kubeconfig: %w", err)
        }
    }

    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
    }

    return &k8sClient{clientset: clientset}, nil
}

// validateToken validates a Service Account token using TokenReview API.
// Returns the authenticated identity on success.
func (c *k8sClient) validateToken(ctx context.Context, token string) (*k8sIdentity, error) {
    review := &authv1.TokenReview{
        Spec: authv1.TokenReviewSpec{
            Token: token,
        },
    }

    result, err := c.clientset.AuthenticationV1().TokenReviews().Create(
        ctx, review, metav1.CreateOptions{},
    )
    if err != nil {
        return nil, fmt.Errorf("tokenreview api call failed: %w", err)
    }

    if !result.Status.Authenticated {
        return nil, fmt.Errorf("token authentication failed: %s", result.Status.Error)
    }

    // Parse username: system:serviceaccount:NAMESPACE:SERVICEACCOUNT
    username := result.Status.User.Username
    namespace, serviceAccount, err := parseServiceAccountUsername(username)
    if err != nil {
        return nil, err
    }

    return &k8sIdentity{
        namespace:      namespace,
        serviceAccount: serviceAccount,
        podName:        extractPodName(result.Status.User.Extra),
        username:       username,
    }, nil
}

// parseServiceAccountUsername parses "system:serviceaccount:NS:SA" format.
func parseServiceAccountUsername(username string) (namespace, serviceAccount string, err error) {
    const prefix = "system:serviceaccount:"
    if !strings.HasPrefix(username, prefix) {
        return "", "", fmt.Errorf("invalid service account username format: %s", username)
    }

    parts := strings.SplitN(username[len(prefix):], ":", 2)
    if len(parts) != 2 {
        return "", "", fmt.Errorf("invalid service account username: %s", username)
    }

    return parts[0], parts[1], nil
}

// extractPodName attempts to extract pod name from user extra fields.
// Returns empty string if not available (non-critical).
func extractPodName(extra map[string]authv1.ExtraValue) string {
    if podNames, ok := extra["authentication.kubernetes.io/pod-name"]; ok && len(podNames) > 0 {
        return podNames[0]
    }
    return ""
}
```

#### `cmd/veilwarden/k8s_identity.go`

Identity structure for Kubernetes workloads.

```go
package main

// k8sIdentity represents an authenticated Kubernetes workload.
type k8sIdentity struct {
    namespace      string
    serviceAccount string
    podName        string // May be empty if not available
    username       string // Full username: system:serviceaccount:NS:SA
}

func (i *k8sIdentity) Type() string {
    return "kubernetes"
}

func (i *k8sIdentity) Attributes() map[string]string {
    attrs := map[string]string{
        "namespace":       i.namespace,
        "service_account": i.serviceAccount,
        "username":        i.username,
    }
    if i.podName != "" {
        attrs["pod_name"] = i.podName
    }
    return attrs
}

// PolicyInput returns the input map for OPA policy evaluation.
func (i *k8sIdentity) PolicyInput() map[string]interface{} {
    input := map[string]interface{}{
        "namespace":       i.namespace,
        "service_account": i.serviceAccount,
        "username":        i.username,
    }
    if i.podName != "" {
        input["pod_name"] = i.podName
    }
    return input
}
```

#### `cmd/veilwarden/k8s_auth.go`

Authentication handler for Kubernetes tokens.

```go
package main

import (
    "context"
    "fmt"
    "strings"
)

// k8sAuthenticator handles Kubernetes Service Account token authentication.
type k8sAuthenticator struct {
    client  *k8sClient
    enabled bool
}

// newK8sAuthenticator creates a new Kubernetes authenticator.
// If enabled=true, requires Kubernetes API access (fails if unavailable).
// If enabled=false, returns disabled authenticator (always returns nil).
func newK8sAuthenticator(enabled bool) (*k8sAuthenticator, error) {
    if !enabled {
        return &k8sAuthenticator{enabled: false}, nil
    }

    client, err := newK8sClient()
    if err != nil {
        return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
    }

    return &k8sAuthenticator{
        client:  client,
        enabled: true,
    }, nil
}

// authenticate validates a Kubernetes Service Account token.
// Returns nil if token is invalid or authenticator is disabled.
func (a *k8sAuthenticator) authenticate(ctx context.Context, token string) (*k8sIdentity, error) {
    if !a.enabled {
        return nil, fmt.Errorf("kubernetes authentication disabled")
    }

    return a.client.validateToken(ctx, token)
}
```

### Modified Files

#### `cmd/veilwarden/config.go`

Add Kubernetes configuration section.

```go
type appConfig struct {
    routes  []route
    secrets []staticSecret
    policy  policyConfig
    kubernetes kubernetesConfig  // NEW
}

// NEW struct
type kubernetesConfig struct {
    enabled      string // "auto", "true", "false"
    apiServer    string
    tokenPath    string
    validateMethod string // "tokenreview", "jwks" (future)
}

func parseConfig(path string) (*appConfig, error) {
    // ... existing code ...

    // Parse kubernetes config (NEW)
    k8sCfg := kubernetesConfig{
        enabled:        "auto", // default
        apiServer:      "https://kubernetes.default.svc",
        tokenPath:      "/var/run/secrets/kubernetes.io/serviceaccount/token",
        validateMethod: "tokenreview",
    }

    if k8sNode, ok := root["kubernetes"]; ok {
        k8sMap := k8sNode.(map[string]interface{})
        if enabled, ok := k8sMap["enabled"].(string); ok {
            k8sCfg.enabled = enabled
        }
        if apiServer, ok := k8sMap["api_server"].(string); ok {
            k8sCfg.apiServer = apiServer
        }
        // ... parse other fields
    }

    return &appConfig{
        routes:     routes,
        secrets:    secrets,
        policy:     policyCfg,
        kubernetes: k8sCfg,  // NEW
    }, nil
}
```

#### `cmd/veilwarden/server.go`

Integrate dual-mode authentication.

**Add field to proxyServer:**
```go
type proxyServer struct {
    routes         []route
    sessionSecret  string
    secretStore    secretStore
    metadata       *metadata
    policyEngine   policyEngine
    k8sAuth        *k8sAuthenticator  // NEW
    userID         string
    userEmail      string
    userOrg        string
}
```

**Update constructor:**
```go
func newProxyServer(
    routes []route,
    sessionSecret string,
    store secretStore,
    meta *metadata,
    policyEngine policyEngine,
    k8sAuth *k8sAuthenticator,  // NEW parameter
    userID, userEmail, userOrg string,
) *proxyServer {
    return &proxyServer{
        routes:        routes,
        sessionSecret: sessionSecret,
        secretStore:   store,
        metadata:      meta,
        policyEngine:  policyEngine,
        k8sAuth:       k8sAuth,  // NEW
        userID:        userID,
        userEmail:     userEmail,
        userOrg:       userOrg,
    }
}
```

**Add authentication method:**
```go
// authenticate validates the request using Kubernetes token or session secret.
// Priority: 1) K8s bearer token, 2) Session secret (backwards compat).
func (s *proxyServer) authenticate(r *http.Request) (identity, error) {
    // Priority 1: Kubernetes Service Account token
    if s.k8sAuth != nil && s.k8sAuth.enabled {
        authHeader := r.Header.Get("Authorization")
        if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
            token := strings.TrimPrefix(authHeader, "Bearer ")
            k8sIdent, err := s.k8sAuth.authenticate(r.Context(), token)
            if err != nil {
                return nil, fmt.Errorf("kubernetes authentication failed: %w", err)
            }
            return k8sIdent, nil
        }
    }

    // Priority 2: Session secret (backwards compatibility)
    sessionSecret := r.Header.Get("X-Session-Secret")
    if sessionSecret == "" {
        return nil, fmt.Errorf("missing authentication: no bearer token or session secret")
    }

    if sessionSecret != s.sessionSecret {
        return nil, fmt.Errorf("invalid session secret")
    }

    // Return static user identity from config
    return &staticIdentity{
        userID:    s.userID,
        userEmail: s.userEmail,
        userOrg:   s.userOrg,
    }, nil
}
```

**Update ServeHTTP to use authentication:**
```go
func (s *proxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // ... existing health check ...

    // Authenticate request (NEW)
    ident, err := s.authenticate(r)
    if err != nil {
        respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error())
        return
    }

    // ... rest of existing logic, use ident for policy evaluation ...

    // Build policy input with identity attributes
    if s.policyEngine != nil {
        policyInput := buildPolicyInput(r, upstreamHost, ident)
        allowed, err := s.policyEngine.evaluate(r.Context(), policyInput)
        // ... existing policy check logic ...
    }
}
```

#### `cmd/veilwarden/policy.go`

Update policy input to use identity interface.

**Define identity interface:**
```go
// identity represents an authenticated entity (user or workload).
type identity interface {
    Type() string                         // "static", "kubernetes"
    Attributes() map[string]string        // All identity attributes
    PolicyInput() map[string]interface{}  // OPA policy input fields
}

// staticIdentity represents static user identity from config.
type staticIdentity struct {
    userID    string
    userEmail string
    userOrg   string
}

func (i *staticIdentity) Type() string {
    return "static"
}

func (i *staticIdentity) Attributes() map[string]string {
    return map[string]string{
        "user_id":    i.userID,
        "user_email": i.userEmail,
        "user_org":   i.userOrg,
    }
}

func (i *staticIdentity) PolicyInput() map[string]interface{} {
    return map[string]interface{}{
        "user_id":    i.userID,
        "user_email": i.userEmail,
        "user_org":   i.userOrg,
    }
}
```

**Update buildPolicyInput:**
```go
func buildPolicyInput(r *http.Request, upstreamHost string, ident identity) map[string]interface{} {
    agentID := r.Header.Get("X-Agent-Id")
    requestID := r.Header.Get("X-Request-Id")
    if requestID == "" {
        requestID = generateRequestID()
    }

    input := map[string]interface{}{
        "method":        r.Method,
        "path":          r.URL.Path,
        "query":         r.URL.RawQuery,
        "upstream_host": upstreamHost,
        "agent_id":      agentID,
        "request_id":    requestID,
        "timestamp":     time.Now().UTC().Format(time.RFC3339),
    }

    // Merge identity-specific fields (NEW)
    for k, v := range ident.PolicyInput() {
        input[k] = v
    }

    return input
}
```

#### `cmd/veilwarden/main.go`

Wire up Kubernetes authenticator.

**Add CLI flags:**
```go
var (
    // ... existing flags ...

    // Kubernetes flags (NEW)
    k8sEnabled      = flag.String("k8s-enabled", "auto", "Enable Kubernetes authentication (auto/true/false)")
    k8sAPIServer    = flag.String("k8s-api-server", "https://kubernetes.default.svc", "Kubernetes API server URL")
    k8sValidateMethod = flag.String("k8s-validate-method", "tokenreview", "Token validation method (tokenreview)")
)
```

**Update main():**
```go
func main() {
    flag.Parse()

    // ... load config ...

    // Initialize Kubernetes authenticator (NEW)
    var k8sAuth *k8sAuthenticator
    k8sEnabledValue := cfg.kubernetes.enabled
    if *k8sEnabled != "auto" {
        k8sEnabledValue = *k8sEnabled
    }

    shouldEnableK8s := false
    if k8sEnabledValue == "true" {
        shouldEnableK8s = true
    } else if k8sEnabledValue == "auto" {
        // Auto-detect: check if we're in Kubernetes
        _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token")
        shouldEnableK8s = (err == nil)
    }

    if shouldEnableK8s {
        var err error
        k8sAuth, err = newK8sAuthenticator(true)
        if err != nil {
            log.Fatalf("failed to initialize kubernetes authenticator: %v", err)
        }
        log.Println("Kubernetes authentication enabled")
    }

    // ... rest of initialization ...

    // Create proxy server with k8sAuth
    proxyServer := newProxyServer(
        cfg.routes,
        *sessionSecret,
        store,
        meta,
        policyEngine,
        k8sAuth,  // NEW
        *userID,
        *userEmail,
        *userOrg,
    )

    // ... start server ...
}
```

### Verification Steps

1. **Unit tests pass:**
   ```bash
   go test ./cmd/veilwarden -run TestK8s
   ```

2. **Manual test with session secret (backwards compatibility):**
   ```bash
   curl -H "X-Session-Secret: dev-secret" http://localhost:8088/test
   # Should work as before
   ```

3. **Build succeeds:**
   ```bash
   go build ./cmd/veilwarden
   ```

**Deliverable:** Core token validation implemented, backwards compatible with session secrets.

---

## Milestone 2: Unit Tests

**Goal:** Comprehensive unit tests for Kubernetes authentication components.

### New Files

#### `cmd/veilwarden/k8s_auth_test.go`

```go
package main

import (
    "context"
    "testing"

    authv1 "k8s.io/api/authentication/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes/fake"
)

func TestK8sAuthenticatorDisabled(t *testing.T) {
    auth, err := newK8sAuthenticator(false)
    if err != nil {
        t.Fatalf("newK8sAuthenticator(false) failed: %v", err)
    }

    _, err = auth.authenticate(context.Background(), "fake-token")
    if err == nil {
        t.Fatal("expected error when authenticator disabled")
    }
    if !strings.Contains(err.Error(), "disabled") {
        t.Errorf("expected 'disabled' error, got: %v", err)
    }
}

func TestK8sClientValidateToken(t *testing.T) {
    fakeClient := fake.NewSimpleClientset()
    client := &k8sClient{clientset: fakeClient}

    // Setup fake response
    fakeClient.PrependReactor("create", "tokenreviews", func(action testing2.Action) (bool, runtime.Object, error) {
        review := &authv1.TokenReview{
            Status: authv1.TokenReviewStatus{
                Authenticated: true,
                User: authv1.UserInfo{
                    Username: "system:serviceaccount:default:test-sa",
                    Extra: map[string]authv1.ExtraValue{
                        "authentication.kubernetes.io/pod-name": {"test-pod"},
                    },
                },
            },
        }
        return true, review, nil
    })

    identity, err := client.validateToken(context.Background(), "valid-token")
    if err != nil {
        t.Fatalf("validateToken failed: %v", err)
    }

    if identity.namespace != "default" {
        t.Errorf("expected namespace 'default', got %q", identity.namespace)
    }
    if identity.serviceAccount != "test-sa" {
        t.Errorf("expected serviceAccount 'test-sa', got %q", identity.serviceAccount)
    }
    if identity.podName != "test-pod" {
        t.Errorf("expected podName 'test-pod', got %q", identity.podName)
    }
}

func TestK8sClientValidateTokenFailed(t *testing.T) {
    fakeClient := fake.NewSimpleClientset()
    client := &k8sClient{clientset: fakeClient}

    // Setup fake failure response
    fakeClient.PrependReactor("create", "tokenreviews", func(action testing2.Action) (bool, runtime.Object, error) {
        review := &authv1.TokenReview{
            Status: authv1.TokenReviewStatus{
                Authenticated: false,
                Error:         "token expired",
            },
        }
        return true, review, nil
    })

    _, err := client.validateToken(context.Background(), "expired-token")
    if err == nil {
        t.Fatal("expected error for expired token")
    }
    if !strings.Contains(err.Error(), "expired") {
        t.Errorf("expected 'expired' error, got: %v", err)
    }
}
```

#### `cmd/veilwarden/k8s_identity_test.go`

```go
package main

import (
    "testing"
)

func TestK8sIdentityType(t *testing.T) {
    identity := &k8sIdentity{
        namespace:      "production",
        serviceAccount: "api-server",
        podName:        "api-server-7d9f8",
    }

    if identity.Type() != "kubernetes" {
        t.Errorf("expected type 'kubernetes', got %q", identity.Type())
    }
}

func TestK8sIdentityAttributes(t *testing.T) {
    identity := &k8sIdentity{
        namespace:      "production",
        serviceAccount: "api-server",
        podName:        "api-server-7d9f8",
        username:       "system:serviceaccount:production:api-server",
    }

    attrs := identity.Attributes()

    tests := []struct {
        key      string
        expected string
    }{
        {"namespace", "production"},
        {"service_account", "api-server"},
        {"pod_name", "api-server-7d9f8"},
        {"username", "system:serviceaccount:production:api-server"},
    }

    for _, tt := range tests {
        if attrs[tt.key] != tt.expected {
            t.Errorf("expected %s=%q, got %q", tt.key, tt.expected, attrs[tt.key])
        }
    }
}

func TestK8sIdentityPolicyInput(t *testing.T) {
    identity := &k8sIdentity{
        namespace:      "staging",
        serviceAccount: "worker",
        podName:        "worker-abc123",
    }

    input := identity.PolicyInput()

    if input["namespace"] != "staging" {
        t.Errorf("expected namespace 'staging', got %v", input["namespace"])
    }
    if input["service_account"] != "worker" {
        t.Errorf("expected service_account 'worker', got %v", input["service_account"])
    }
    if input["pod_name"] != "worker-abc123" {
        t.Errorf("expected pod_name 'worker-abc123', got %v", input["pod_name"])
    }
}

func TestK8sIdentityPolicyInputWithoutPodName(t *testing.T) {
    identity := &k8sIdentity{
        namespace:      "default",
        serviceAccount: "default",
        podName:        "", // Not available
    }

    input := identity.PolicyInput()

    if _, exists := input["pod_name"]; exists {
        t.Error("pod_name should not be in policy input when empty")
    }
}
```

#### `cmd/veilwarden/server_test.go` (additions)

```go
func TestProxyServerAuthenticateK8s(t *testing.T) {
    // Setup fake Kubernetes client
    fakeClient := fake.NewSimpleClientset()
    k8sAuth := &k8sAuthenticator{
        client:  &k8sClient{clientset: fakeClient},
        enabled: true,
    }

    // Setup fake TokenReview response
    fakeClient.PrependReactor("create", "tokenreviews", func(action testing2.Action) (bool, runtime.Object, error) {
        review := &authv1.TokenReview{
            Status: authv1.TokenReviewStatus{
                Authenticated: true,
                User: authv1.UserInfo{
                    Username: "system:serviceaccount:default:test-sa",
                },
            },
        }
        return true, review, nil
    })

    proxy := &proxyServer{
        sessionSecret: "test-secret",
        k8sAuth:       k8sAuth,
    }

    // Test Kubernetes authentication
    req := httptest.NewRequest("GET", "/test", nil)
    req.Header.Set("Authorization", "Bearer valid-k8s-token")

    identity, err := proxy.authenticate(req)
    if err != nil {
        t.Fatalf("authenticate failed: %v", err)
    }

    k8sIdent, ok := identity.(*k8sIdentity)
    if !ok {
        t.Fatalf("expected k8sIdentity, got %T", identity)
    }

    if k8sIdent.namespace != "default" {
        t.Errorf("expected namespace 'default', got %q", k8sIdent.namespace)
    }
    if k8sIdent.serviceAccount != "test-sa" {
        t.Errorf("expected serviceAccount 'test-sa', got %q", k8sIdent.serviceAccount)
    }
}

func TestProxyServerAuthenticateSessionSecret(t *testing.T) {
    proxy := &proxyServer{
        sessionSecret: "test-secret",
        k8sAuth:       &k8sAuthenticator{enabled: false},
        userID:        "alice",
        userEmail:     "alice@example.com",
        userOrg:       "engineering",
    }

    req := httptest.NewRequest("GET", "/test", nil)
    req.Header.Set("X-Session-Secret", "test-secret")

    identity, err := proxy.authenticate(req)
    if err != nil {
        t.Fatalf("authenticate failed: %v", err)
    }

    staticIdent, ok := identity.(*staticIdentity)
    if !ok {
        t.Fatalf("expected staticIdentity, got %T", identity)
    }

    if staticIdent.userID != "alice" {
        t.Errorf("expected userID 'alice', got %q", staticIdent.userID)
    }
}

func TestProxyServerAuthenticatePriority(t *testing.T) {
    // Test that K8s token takes priority over session secret

    fakeClient := fake.NewSimpleClientset()
    k8sAuth := &k8sAuthenticator{
        client:  &k8sClient{clientset: fakeClient},
        enabled: true,
    }

    fakeClient.PrependReactor("create", "tokenreviews", func(action testing2.Action) (bool, runtime.Object, error) {
        review := &authv1.TokenReview{
            Status: authv1.TokenReviewStatus{
                Authenticated: true,
                User: authv1.UserInfo{
                    Username: "system:serviceaccount:prod:api",
                },
            },
        }
        return true, review, nil
    })

    proxy := &proxyServer{
        sessionSecret: "session-secret",
        k8sAuth:       k8sAuth,
        userID:        "alice",
    }

    // Request with BOTH Bearer token and session secret
    req := httptest.NewRequest("GET", "/test", nil)
    req.Header.Set("Authorization", "Bearer k8s-token")
    req.Header.Set("X-Session-Secret", "session-secret")

    identity, err := proxy.authenticate(req)
    if err != nil {
        t.Fatalf("authenticate failed: %v", err)
    }

    // Should use K8s identity (higher priority)
    if identity.Type() != "kubernetes" {
        t.Errorf("expected kubernetes identity, got %s", identity.Type())
    }
}
```

### Verification Steps

1. **All unit tests pass:**
   ```bash
   go test -v ./cmd/veilwarden
   ```

2. **Test coverage for new code:**
   ```bash
   go test -cover ./cmd/veilwarden
   # Should show >80% coverage for k8s_*.go files
   ```

**Deliverable:** Comprehensive unit test coverage for Kubernetes authentication.

---

## Milestone 3: Integration Tests with EnvTest

**Goal:** Test Kubernetes authentication against a real Kubernetes API server using EnvTest.

### New Files

#### `cmd/veilwarden/integration_k8s_test.go`

```go
//go:build integration
// +build integration

package main

import (
    "context"
    "path/filepath"
    "testing"
    "time"

    authv1 "k8s.io/api/authentication/v1"
    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
    "sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestK8sAuthenticationIntegration(t *testing.T) {
    // Start EnvTest (real API server)
    testEnv := &envtest.Environment{
        CRDDirectoryPaths: []string{},
    }

    cfg, err := testEnv.Start()
    if err != nil {
        t.Fatalf("failed to start test environment: %v", err)
    }
    defer testEnv.Stop()

    // Create Kubernetes client
    clientset, err := kubernetes.NewForConfig(cfg)
    if err != nil {
        t.Fatalf("failed to create clientset: %v", err)
    }

    // Create test namespace
    ns := &corev1.Namespace{
        ObjectMeta: metav1.ObjectMeta{
            Name: "test-integration",
        },
    }
    _, err = clientset.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
    if err != nil {
        t.Fatalf("failed to create namespace: %v", err)
    }

    // Create test ServiceAccount
    sa := &corev1.ServiceAccount{
        ObjectMeta: metav1.ObjectMeta{
            Name:      "test-sa",
            Namespace: "test-integration",
        },
    }
    _, err = clientset.CoreV1().ServiceAccounts("test-integration").Create(context.Background(), sa, metav1.CreateOptions{})
    if err != nil {
        t.Fatalf("failed to create service account: %v", err)
    }

    // Wait for token to be created
    time.Sleep(2 * time.Second)

    // Get ServiceAccount token
    sa, err = clientset.CoreV1().ServiceAccounts("test-integration").Get(context.Background(), "test-sa", metav1.GetOptions{})
    if err != nil {
        t.Fatalf("failed to get service account: %v", err)
    }

    if len(sa.Secrets) == 0 {
        t.Fatal("service account has no secrets")
    }

    secret, err := clientset.CoreV1().Secrets("test-integration").Get(context.Background(), sa.Secrets[0].Name, metav1.GetOptions{})
    if err != nil {
        t.Fatalf("failed to get secret: %v", err)
    }

    token := string(secret.Data["token"])
    if token == "" {
        t.Fatal("token is empty")
    }

    // Test token validation
    client := &k8sClient{clientset: clientset}
    identity, err := client.validateToken(context.Background(), token)
    if err != nil {
        t.Fatalf("validateToken failed: %v", err)
    }

    if identity.namespace != "test-integration" {
        t.Errorf("expected namespace 'test-integration', got %q", identity.namespace)
    }
    if identity.serviceAccount != "test-sa" {
        t.Errorf("expected serviceAccount 'test-sa', got %q", identity.serviceAccount)
    }
}

func TestK8sAuthenticationIntegrationInvalidToken(t *testing.T) {
    testEnv := &envtest.Environment{}
    cfg, err := testEnv.Start()
    if err != nil {
        t.Fatalf("failed to start test environment: %v", err)
    }
    defer testEnv.Stop()

    clientset, err := kubernetes.NewForConfig(cfg)
    if err != nil {
        t.Fatalf("failed to create clientset: %v", err)
    }

    client := &k8sClient{clientset: clientset}

    // Test with invalid token
    _, err = client.validateToken(context.Background(), "invalid-token")
    if err == nil {
        t.Fatal("expected error for invalid token")
    }
}
```

### Build Tags and Makefile

#### `Makefile`

```makefile
.PHONY: test
test:
	go test -v ./cmd/veilwarden

.PHONY: test-integration
test-integration:
	go test -v -tags=integration ./cmd/veilwarden

.PHONY: test-all
test-all: test test-integration
```

### Verification Steps

1. **Install EnvTest binaries:**
   ```bash
   go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
   setup-envtest use 1.31.0
   ```

2. **Run integration tests:**
   ```bash
   make test-integration
   # Should start API server and pass all integration tests
   ```

3. **CI Integration:**
   ```yaml
   # .github/workflows/test.yml (example)
   - name: Run integration tests
     run: |
       setup-envtest use 1.31.0
       make test-integration
   ```

**Deliverable:** Integration tests using real Kubernetes API server (EnvTest).

---

## Milestone 4: E2E Tests with kind

**Goal:** End-to-end tests in a real Kubernetes cluster using kind.

### New Files

#### `cmd/veilwarden/e2e_k8s_test.go`

```go
//go:build e2e
// +build e2e

package main

import (
    "context"
    "fmt"
    "net/http"
    "os"
    "testing"
    "time"

    corev1 "k8s.io/api/core/v1"
    rbacv1 "k8s.io/api/rbac/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/clientcmd"
)

// TestE2EKubernetesWorkloadIdentity tests full Kubernetes integration.
// Prerequisites:
//   - kind cluster running
//   - KUBECONFIG set to kind cluster
func TestE2EKubernetesWorkloadIdentity(t *testing.T) {
    kubeconfig := os.Getenv("KUBECONFIG")
    if kubeconfig == "" {
        t.Skip("KUBECONFIG not set, skipping e2e test")
    }

    config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
    if err != nil {
        t.Fatalf("failed to build config: %v", err)
    }

    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        t.Fatalf("failed to create clientset: %v", err)
    }

    ctx := context.Background()

    // Create test namespace
    namespace := "veilwarden-e2e"
    ns := &corev1.Namespace{
        ObjectMeta: metav1.ObjectMeta{Name: namespace},
    }
    _, err = clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
    if err != nil {
        t.Logf("namespace may already exist: %v", err)
    }
    defer clientset.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{})

    // Create ServiceAccount
    sa := &corev1.ServiceAccount{
        ObjectMeta: metav1.ObjectMeta{
            Name:      "test-workload",
            Namespace: namespace,
        },
    }
    _, err = clientset.CoreV1().ServiceAccounts(namespace).Create(ctx, sa, metav1.CreateOptions{})
    if err != nil {
        t.Fatalf("failed to create service account: %v", err)
    }

    // Create ClusterRole for TokenReview
    clusterRole := &rbacv1.ClusterRole{
        ObjectMeta: metav1.ObjectMeta{
            Name: "veilwarden-tokenreview",
        },
        Rules: []rbacv1.PolicyRule{
            {
                APIGroups: []string{"authentication.k8s.io"},
                Resources: []string{"tokenreviews"},
                Verbs:     []string{"create"},
            },
        },
    }
    _, err = clientset.RbacV1().ClusterRoles().Create(ctx, clusterRole, metav1.CreateOptions{})
    if err != nil {
        t.Logf("clusterrole may already exist: %v", err)
    }

    // Create ClusterRoleBinding
    binding := &rbacv1.ClusterRoleBinding{
        ObjectMeta: metav1.ObjectMeta{
            Name: "veilwarden-tokenreview-binding",
        },
        RoleRef: rbacv1.RoleRef{
            APIGroup: "rbac.authorization.k8s.io",
            Kind:     "ClusterRole",
            Name:     "veilwarden-tokenreview",
        },
        Subjects: []rbacv1.Subject{
            {
                Kind:      "ServiceAccount",
                Name:      "veilwarden",
                Namespace: namespace,
            },
        },
    }
    _, err = clientset.RbacV1().ClusterRoleBindings().Create(ctx, binding, metav1.CreateOptions{})
    if err != nil {
        t.Logf("binding may already exist: %v", err)
    }

    // Wait for token
    time.Sleep(3 * time.Second)

    // Get token
    sa, err = clientset.CoreV1().ServiceAccounts(namespace).Get(ctx, "test-workload", metav1.GetOptions{})
    if err != nil {
        t.Fatalf("failed to get service account: %v", err)
    }

    if len(sa.Secrets) == 0 {
        t.Fatal("service account has no secrets")
    }

    secret, err := clientset.CoreV1().Secrets(namespace).Get(ctx, sa.Secrets[0].Name, metav1.GetOptions{})
    if err != nil {
        t.Fatalf("failed to get secret: %v", err)
    }

    token := string(secret.Data["token"])

    // Start veilwarden proxy (assumes it's been deployed or we start it locally pointing at cluster)
    // For simplicity, this test assumes proxy is already running
    proxyURL := os.Getenv("VEILWARDEN_URL")
    if proxyURL == "" {
        proxyURL = "http://localhost:8088"
    }

    // Make request with Kubernetes token
    req, _ := http.NewRequest("GET", proxyURL+"/test", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("X-Upstream-Host", "httpbin.org")

    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        t.Fatalf("request failed: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        t.Errorf("expected status 200, got %d", resp.StatusCode)
    }

    t.Log("E2E test with Kubernetes workload identity passed")
}
```

#### `scripts/test_k8s_e2e.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "Creating kind cluster..."
kind create cluster --name veilwarden-test --wait 5m

export KUBECONFIG="$(kind get kubeconfig --name veilwarden-test)"

echo "Building veilwarden image..."
docker build -t veilwarden:test .

echo "Loading image into kind..."
kind load docker-image veilwarden:test --name veilwarden-test

echo "Deploying veilwarden..."
kubectl apply -f deploy/kubernetes/

echo "Waiting for deployment..."
kubectl rollout status daemonset/veilwarden -n veilwarden

echo "Running e2e tests..."
go test -v -tags=e2e ./cmd/veilwarden

echo "Cleaning up..."
kind delete cluster --name veilwarden-test
```

### Verification Steps

1. **Create kind cluster:**
   ```bash
   kind create cluster --name veilwarden-test
   ```

2. **Run E2E test script:**
   ```bash
   ./scripts/test_k8s_e2e.sh
   ```

3. **Manual verification:**
   ```bash
   # Deploy veilwarden to kind cluster
   kubectl apply -f deploy/kubernetes/

   # Get pod token
   kubectl exec -it veilwarden-xxxxx -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

   # Test with token
   curl -H "Authorization: Bearer <token>" http://localhost:8088/test
   ```

**Deliverable:** E2E tests running in real kind cluster with Service Account tokens.

---

## Milestone 5: Deployment Manifests

**Goal:** Production-ready Kubernetes deployment manifests.

### New Directory Structure

```
deploy/kubernetes/
├── namespace.yaml
├── serviceaccount.yaml
├── clusterrole.yaml
├── clusterrolebinding.yaml
├── configmap.yaml
├── daemonset.yaml
└── kustomization.yaml
```

### Files

#### `deploy/kubernetes/namespace.yaml`

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: veilwarden
```

#### `deploy/kubernetes/serviceaccount.yaml`

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: veilwarden
  namespace: veilwarden
```

#### `deploy/kubernetes/clusterrole.yaml`

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: veilwarden-tokenreview
rules:
- apiGroups: ["authentication.k8s.io"]
  resources: ["tokenreviews"]
  verbs: ["create"]
```

#### `deploy/kubernetes/clusterrolebinding.yaml`

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: veilwarden-tokenreview
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: veilwarden-tokenreview
subjects:
- kind: ServiceAccount
  name: veilwarden
  namespace: veilwarden
```

#### `deploy/kubernetes/configmap.yaml`

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: veilwarden-config
  namespace: veilwarden
data:
  config.yaml: |
    routes:
      - upstream_host: api.github.com
        upstream_scheme: https
        secret_id: GITHUB_TOKEN
        inject_header: Authorization
        header_value_template: "token {{secret}}"

    kubernetes:
      enabled: auto
      validate_method: tokenreview

    policy:
      enabled: true
      engine: opa
      policy_path: /etc/veilwarden/policies
      decision_path: veilwarden/authz/allow
```

#### `deploy/kubernetes/daemonset.yaml`

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: veilwarden
  namespace: veilwarden
  labels:
    app: veilwarden
spec:
  selector:
    matchLabels:
      app: veilwarden
  template:
    metadata:
      labels:
        app: veilwarden
    spec:
      serviceAccountName: veilwarden
      hostNetwork: true  # Node-local proxy
      containers:
      - name: veilwarden
        image: veilwarden:latest
        imagePullPolicy: IfNotPresent
        args:
        - --config=/etc/veilwarden/config.yaml
        - --k8s-enabled=auto
        ports:
        - name: proxy
          containerPort: 8088
          hostPort: 8088
          protocol: TCP
        env:
        - name: VEILWARDEN_SESSION_SECRET
          valueFrom:
            secretKeyRef:
              name: veilwarden-secrets
              key: session-secret
        - name: DOPPLER_TOKEN
          valueFrom:
            secretKeyRef:
              name: veilwarden-secrets
              key: doppler-token
        - name: DOPPLER_PROJECT
          value: veilwarden
        - name: DOPPLER_CONFIG
          value: production
        volumeMounts:
        - name: config
          mountPath: /etc/veilwarden
          readOnly: true
        - name: policies
          mountPath: /etc/veilwarden/policies
          readOnly: true
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 256Mi
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8088
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /healthz
            port: 8088
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: veilwarden-config
      - name: policies
        configMap:
          name: veilwarden-policies
```

#### `deploy/kubernetes/kustomization.yaml`

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: veilwarden

resources:
- namespace.yaml
- serviceaccount.yaml
- clusterrole.yaml
- clusterrolebinding.yaml
- configmap.yaml
- daemonset.yaml

images:
- name: veilwarden
  newTag: v0.2.0
```

### Verification Steps

1. **Deploy to kind cluster:**
   ```bash
   kubectl apply -k deploy/kubernetes/
   ```

2. **Verify pods running:**
   ```bash
   kubectl get pods -n veilwarden
   kubectl logs -n veilwarden -l app=veilwarden
   ```

3. **Test from pod:**
   ```bash
   kubectl run test-pod --rm -it --image=curlimages/curl -- sh
   # Inside pod:
   TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
   curl -H "Authorization: Bearer $TOKEN" \
        -H "X-Upstream-Host: httpbin.org" \
        http://localhost:8088/headers
   ```

**Deliverable:** Production-ready Kubernetes manifests for DaemonSet deployment.

---

## Milestone 6: Documentation Updates

**Goal:** Update README and create user guides.

### Files to Update

#### `README.md`

Add new section after "OPA Policy Integration":

```markdown
## Kubernetes Workload Identity

Veilwarden supports native Kubernetes Service Account authentication, allowing pods to authenticate using their SA tokens instead of static credentials.

### Quick Start (Kubernetes)

1. **Deploy veilwarden as a DaemonSet:**
   ```bash
   kubectl apply -k deploy/kubernetes/
   ```

2. **Configure your application pod to use the node-local proxy:**
   ```yaml
   apiVersion: v1
   kind: Pod
   metadata:
     name: my-app
   spec:
     containers:
     - name: app
       image: my-app:latest
       env:
       - name: HTTP_PROXY
         value: "http://localhost:8088"
       - name: VEILWARDEN_TOKEN
         valueFrom:
           secretKeyFrom:
             name: kubernetes.io/serviceaccount
             key: token
   ```

3. **Make requests through the proxy:**
   ```bash
   curl -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
        -H "X-Upstream-Host: api.github.com" \
        http://localhost:8088/repos
   ```

### Policy-Based Access Control

Use OPA policies to control which workloads can access which APIs:

```rego
package veilwarden.authz

# Only allow production namespace to access Stripe API
allow if {
    input.namespace == "production"
    input.upstream_host == "api.stripe.com"
}

# Allow CI/CD pipeline to access GitHub
allow if {
    input.service_account == "github-actions"
    input.upstream_host == "api.github.com"
}
```

See `docs/kubernetes-workload-identity.md` for complete documentation.
```

#### `docs/kubernetes-usage-guide.md` (new file)

```markdown
# Kubernetes Usage Guide

## Installation

### Prerequisites
- Kubernetes 1.25+
- Doppler account (or other secret backend)
- kubectl configured

### Deploy with kubectl

Deploy veilwarden to your cluster:

```bash
kubectl apply -k deploy/kubernetes/
```

This creates:
- Namespace: `veilwarden`
- ServiceAccount: `veilwarden` with TokenReview permissions
- DaemonSet: One proxy pod per node on `localhost:8088`

### Configure Secrets

Create secret with Doppler credentials:

```bash
kubectl create secret generic veilwarden-secrets \
  -n veilwarden \
  --from-literal=session-secret=$(openssl rand -hex 32) \
  --from-literal=doppler-token=$DOPPLER_TOKEN
```

## Using from Application Pods

### Method 1: Direct API calls

```go
package main

import (
    "fmt"
    "io"
    "net/http"
    "os"
)

func main() {
    // Read pod's Service Account token
    token, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")

    req, _ := http.NewRequest("GET", "http://localhost:8088/v1/charges", nil)
    req.Header.Set("Authorization", "Bearer "+string(token))
    req.Header.Set("X-Upstream-Host", "api.stripe.com")

    resp, _ := http.DefaultClient.Do(req)
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
}
```

### Method 2: HTTP_PROXY environment variable

Configure your application to use veilwarden as HTTP proxy:

```yaml
env:
- name: HTTP_PROXY
  value: "http://localhost:8088"
- name: HTTPS_PROXY
  value: "http://localhost:8088"
```

## Policy Examples

See `policies/kubernetes-example.rego` for production policy patterns.

## Troubleshooting

### Pods can't authenticate

Check RBAC permissions:
```bash
kubectl auth can-i create tokenreviews.authentication.k8s.io \
  --as=system:serviceaccount:veilwarden:veilwarden
```

### Policy denials

Check veilwarden logs:
```bash
kubectl logs -n veilwarden -l app=veilwarden | grep policy
```
```

### Verification Steps

1. **Verify documentation builds:**
   ```bash
   # If using mdbook or similar
   mdbook build docs/
   ```

2. **Test README examples:**
   ```bash
   # Follow quickstart commands
   kubectl apply -k deploy/kubernetes/
   ```

**Deliverable:** Complete documentation for Kubernetes integration.

---

## File Structure After Implementation

```
veilwarden/
├── cmd/
│   └── veilwarden/
│       ├── config.go              # Modified: add kubernetesConfig
│       ├── main.go                # Modified: wire up k8sAuth
│       ├── server.go              # Modified: dual-mode auth
│       ├── policy.go              # Modified: identity interface
│       ├── k8s_client.go          # NEW: TokenReview client
│       ├── k8s_auth.go            # NEW: K8s authenticator
│       ├── k8s_identity.go        # NEW: K8s identity type
│       ├── k8s_auth_test.go       # NEW: Unit tests
│       ├── k8s_identity_test.go   # NEW: Unit tests
│       ├── integration_k8s_test.go # NEW: EnvTest integration
│       ├── e2e_k8s_test.go        # NEW: kind E2E tests
│       └── server_test.go         # Modified: add auth tests
├── deploy/
│   └── kubernetes/
│       ├── namespace.yaml         # NEW
│       ├── serviceaccount.yaml    # NEW
│       ├── clusterrole.yaml       # NEW
│       ├── clusterrolebinding.yaml # NEW
│       ├── configmap.yaml         # NEW
│       ├── daemonset.yaml         # NEW
│       └── kustomization.yaml     # NEW
├── docs/
│   ├── kubernetes-workload-identity.md  # CREATED
│   ├── kubernetes-implementation-plan.md # THIS FILE
│   └── kubernetes-usage-guide.md  # NEW
├── policies/
│   └── kubernetes-example.rego    # To be created
├── scripts/
│   └── test_k8s_e2e.sh           # NEW
├── Makefile                       # NEW
├── go.mod                         # Modified: add k8s deps
└── README.md                      # Modified: add K8s section
```

---

## Testing Strategy Summary

| Test Type | Tool | Purpose | Location |
|-----------|------|---------|----------|
| **Unit** | Go `testing` | Token parsing, identity logic | `*_test.go` |
| **Integration** | EnvTest | Real TokenReview API | `integration_k8s_test.go` |
| **E2E** | kind | Full cluster deployment | `e2e_k8s_test.go` |

**Run all tests:**
```bash
# Unit tests
go test ./cmd/veilwarden

# Integration tests
go test -tags=integration ./cmd/veilwarden

# E2E tests (requires kind)
./scripts/test_k8s_e2e.sh
```

---

## Implementation Order

1. **Milestone 1** (Core) → Foundation for K8s auth
2. **Milestone 2** (Unit Tests) → Verify core logic
3. **Milestone 3** (Integration) → Validate against real API server
4. **Milestone 5** (Deployment) → Create manifests (can be parallel with M3)
5. **Milestone 4** (E2E) → Full cluster testing (requires M5 manifests)
6. **Milestone 6** (Docs) → User-facing documentation (final polish)

---

## Verification Checklist

Before considering implementation complete:

- [ ] All unit tests pass (`go test ./cmd/veilwarden`)
- [ ] Integration tests pass with EnvTest
- [ ] E2E tests pass in kind cluster
- [ ] Backwards compatibility: session secret auth still works
- [ ] Dual-mode auth: K8s token takes priority when both present
- [ ] TokenReview API calls succeed with proper RBAC
- [ ] DaemonSet deploys successfully to kind
- [ ] Pod-to-proxy communication works on localhost:8088
- [ ] OPA policies evaluate with K8s identity attributes
- [ ] Documentation examples are tested and working
- [ ] RBAC manifests grant only necessary permissions

---

## Future Enhancements (Out of Scope)

Documented in design doc but not implemented in this phase:

1. **JWKS Validation** - Offline token validation without TokenReview API
2. **Metadata Enrichment** - Fetch pod labels, namespace metadata
3. **Mutual TLS** - Pod-to-proxy authentication
4. **Audit Logging** - Structured logs for compliance
5. **Metrics** - Prometheus metrics for K8s requests

These can be added in future milestones based on user feedback.

---

## Dependencies

**Required Go modules:**
```
k8s.io/api@v0.31.0
k8s.io/apimachinery@v0.31.0
k8s.io/client-go@v0.31.0
sigs.k8s.io/controller-runtime@v0.19.0
```

**Testing tools:**
```bash
# EnvTest
go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
setup-envtest use 1.31.0

# kind (E2E tests)
GO111MODULE=on go install sigs.k8s.io/kind@latest
```

---

## Questions for Reviewers

Before starting implementation:

1. **Auto-detection logic**: Is `enabled: auto` (check for SA token file) acceptable, or prefer explicit configuration?
2. **RBAC scope**: ClusterRole for TokenReview OK, or prefer namespaced Role with limited scope?
3. **DaemonSet vs Deployment**: DaemonSet ensures node-local proxy, but increases resource usage. Alternative: single deployment with NodePort?
4. **Testing depth**: Is EnvTest + kind sufficient, or also test against real GKE/EKS/AKS clusters?

---

## Success Criteria

Implementation is considered complete when:

1. ✅ Kubernetes pods can authenticate using Service Account tokens
2. ✅ TokenReview API successfully validates tokens
3. ✅ OPA policies receive namespace, service_account, pod_name attributes
4. ✅ Backwards compatibility maintained (session secrets still work)
5. ✅ DaemonSet deployment works in kind cluster
6. ✅ E2E test demonstrates full workflow
7. ✅ Documentation allows new users to deploy in <10 minutes
8. ✅ All tests pass in CI

---

## Timeline Estimate

| Milestone | Estimated Time | Dependencies |
|-----------|---------------|--------------|
| M1: Core Token Validation | 2-3 days | None |
| M2: Unit Tests | 1 day | M1 |
| M3: Integration Tests | 1-2 days | M1, M2 |
| M5: Deployment Manifests | 1 day | M1 |
| M4: E2E Tests | 1-2 days | M5 |
| M6: Documentation | 1 day | All |
| **Total** | **7-10 days** | - |

Milestones 3 and 5 can be developed in parallel.

---

## Contact

For questions about this implementation plan:
- Design doc: `docs/kubernetes-workload-identity.md`
- Issues: GitHub issues
- Discussion: Team Slack #veilwarden
