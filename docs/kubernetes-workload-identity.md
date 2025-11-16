# Kubernetes Workload Identity Integration

**Status:** Design Document
**Version:** 1.0
**Last Updated:** 2025-11-16
**Authors:** Claude Code

---

## Executive Summary

This document describes the integration of Kubernetes Workload Identity authentication into veilwarden, enabling pod-based authentication using Service Account tokens. This replaces static user identity with dynamic, per-request workload identity while maintaining backwards compatibility with existing authentication methods.

**Key Features:**
- Authenticate pods using Service Account projected tokens
- Extract identity from JWT claims (namespace, service account, pod name)
- Dual-mode authentication (session secret OR Kubernetes SA token)
- Policy-driven access control based on Kubernetes identity
- DaemonSet deployment model for node-local proxying

**Target Deployment:** Kubernetes 1.22+ (bound Service Account tokens)

---

## Architecture Overview

### Current State

**Authentication:**
- Static session secret (`X-Session-Secret` header)
- Single secret shared across all workloads
- No per-request identity differentiation

**Identity Context:**
- Set via CLI flags at proxy startup (`--user-id`, `--user-email`, `--user-org`)
- Same identity applied to all requests
- Suitable for single-tenant development, not multi-tenant Kubernetes

### Future State

**Authentication:**
- **Option 1:** Session secret (current, for backwards compatibility)
- **Option 2:** Kubernetes Service Account token (new, for K8s workloads)
- Auto-detection based on request headers

**Identity Context:**
- Extracted from Service Account JWT token per-request
- Includes namespace, service account name, pod name
- Enables fine-grained, workload-specific policy decisions

---

## Technical Design

### 1. Service Account Token Projection

**How Kubernetes provides tokens:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
spec:
  serviceAccountName: my-service-account
  containers:
  - name: app
    volumeMounts:
    - name: kube-api-access
      mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      readOnly: true
  # Automatically projected by kubelet
```

**Token location:** `/var/run/secrets/kubernetes.io/serviceaccount/token`

**Token properties:**
- Format: JWT (JSON Web Token)
- Algorithm: RS256 (RSA signature)
- Validity: Time-bound (default 1 hour, auto-rotated)
- Audience-bound: Prevents token forwarding attacks
- Pod-bound: Includes pod metadata in claims

### 2. JWT Token Structure

**Standard JWT claims:**

```json
{
  "iss": "https://kubernetes.default.svc.cluster.local",
  "sub": "system:serviceaccount:default:my-service-account",
  "aud": ["https://kubernetes.default.svc"],
  "exp": 1700000000,
  "iat": 1699996400,
  "nbf": 1699996400
}
```

**Kubernetes-specific claims:**

```json
{
  "kubernetes.io": {
    "namespace": "production",
    "pod": {
      "name": "my-app-abc123",
      "uid": "262a6af2-a6a8-4e0a-bdf9-a47f8f845c46"
    },
    "serviceaccount": {
      "name": "my-service-account",
      "uid": "272e2776-0648-448a-a166-848d0742abf2"
    }
  }
}
```

**Identity extraction mapping:**

| JWT Claim | PolicyInput Field | Example Value |
|-----------|------------------|---------------|
| `kubernetes.io.namespace` | `K8sNamespace` | `production` |
| `kubernetes.io.serviceaccount.name` | `K8sServiceAccount` | `my-service-account` |
| `kubernetes.io.pod.name` | `K8sPodName` | `my-app-abc123` |
| `sub` | *(validation only)* | `system:serviceaccount:production:my-service-account` |

### 3. Token Validation Strategy

**Chosen approach:** TokenReview API

**Rationale:**
- ✅ Official Kubernetes validation mechanism
- ✅ Automatic signature verification, expiration checks
- ✅ No need to manage JWKS (public keys)
- ✅ Handles token rotation automatically
- ✅ Simpler implementation
- ⚠️ Requires network call to API server (acceptable latency)

**Alternative (future optimization):** Local JWT validation with JWKS caching

**Validation flow:**

```
1. Client → veilwarden: HTTP request with Authorization: Bearer <token>
2. veilwarden → K8s API: POST /apis/authentication.k8s.io/v1/tokenreviews
3. K8s API → veilwarden: TokenReview response with identity
4. veilwarden: Extract identity, construct PolicyInput
5. veilwarden → Policy Engine: Evaluate with K8s identity
6. veilwarden → Upstream: Proxy request if allowed
```

**TokenReview API request:**

```json
{
  "apiVersion": "authentication.k8s.io/v1",
  "kind": "TokenReview",
  "spec": {
    "token": "<service-account-token>",
    "audiences": ["https://kubernetes.default.svc"]
  }
}
```

**TokenReview API response:**

```json
{
  "apiVersion": "authentication.k8s.io/v1",
  "kind": "TokenReview",
  "status": {
    "authenticated": true,
    "user": {
      "username": "system:serviceaccount:production:my-service-account",
      "uid": "272e2776-0648-448a-a166-848d0742abf2",
      "groups": ["system:serviceaccounts", "system:serviceaccounts:production"]
    },
    "audiences": ["https://kubernetes.default.svc"]
  }
}
```

### 4. Dual-Mode Authentication

**Auto-detection logic:**

```go
func (s *proxyServer) authenticate(r *http.Request) (Identity, error) {
    // Priority 1: Kubernetes Service Account token
    if authHeader := r.Header.Get("Authorization"); authHeader != "" {
        if strings.HasPrefix(authHeader, "Bearer ") {
            token := strings.TrimPrefix(authHeader, "Bearer ")
            return s.validateK8sToken(r.Context(), token)
        }
    }

    // Priority 2: Session secret (backwards compatibility)
    if sessionSecret := r.Header.Get("X-Session-Secret"); sessionSecret != "" {
        if sessionSecret == s.sessionSecret {
            return s.staticIdentity, nil
        }
        return nil, ErrUnauthorized
    }

    return nil, ErrNoAuthProvided
}
```

**Authentication modes:**

| Mode | Header | Value | Use Case |
|------|--------|-------|----------|
| Kubernetes | `Authorization` | `Bearer <SA-token>` | Production pods |
| Session Secret | `X-Session-Secret` | `<shared-secret>` | Local dev, legacy |

### 5. Identity Representation

**New Identity interface:**

```go
type Identity interface {
    // Authentication method used
    AuthMethod() string  // "kubernetes" | "session"

    // Legacy fields (for session auth)
    UserID() string
    UserEmail() string
    UserOrg() string

    // Kubernetes fields (for K8s auth)
    K8sNamespace() string
    K8sServiceAccount() string
    K8sPodName() string
}

type K8sIdentity struct {
    namespace      string
    serviceAccount string
    podName        string
    podUID         string  // for future use
}

type SessionIdentity struct {
    userID    string
    userEmail string
    userOrg   string
}
```

**PolicyInput updates:**

```go
type PolicyInput struct {
    // Request context
    Method       string
    Path         string
    Query        string
    UpstreamHost string
    SecretID     string

    // Identity context - Kubernetes (NEW)
    K8sNamespace      string
    K8sServiceAccount string
    K8sPodName        string

    // Identity context - Legacy (existing, for backwards compat)
    AgentID   string
    UserID    string
    UserEmail string
    UserOrg   string

    // Metadata
    RequestID string
    Timestamp time.Time
}
```

### 6. Configuration

**Configuration file format:**

```yaml
# Kubernetes authentication settings
kubernetes:
  # Enable Kubernetes authentication
  # Options: auto (detect K8s env), true (force enable), false (disable)
  enabled: auto

  # Kubernetes API server endpoint
  # Default: in-cluster config (https://kubernetes.default.svc)
  api_server: ""

  # Path to service account token
  # Default: /var/run/secrets/kubernetes.io/serviceaccount/token
  token_path: ""

  # Token validation method
  # Options: tokenreview (recommended), jwks (future)
  validate_method: tokenreview

  # Expected token audience (for validation)
  # Default: https://kubernetes.default.svc
  audience: ""
```

**Auto-detection logic:**

```go
func detectKubernetesEnvironment() bool {
    // Check 1: Service account token exists
    if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
        return true
    }

    // Check 2: KUBERNETES_SERVICE_HOST environment variable
    if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
        return true
    }

    return false
}
```

### 7. RBAC Requirements

**Required ClusterRole for veilwarden ServiceAccount:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: veilwarden-authenticator
rules:
  # Required: Validate service account tokens
  - apiGroups: ["authentication.k8s.io"]
    resources: ["tokenreviews"]
    verbs: ["create"]
```

**ClusterRoleBinding:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: veilwarden-authenticator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: veilwarden-authenticator
subjects:
  - kind: ServiceAccount
    name: veilwarden
    namespace: veilwarden-system
```

**Why ClusterRole and not Role:**
- TokenReview is a cluster-scoped resource
- Veilwarden needs to validate tokens from any namespace
- Alternative: Use Role per namespace if namespace isolation required

### 8. Error Handling

**Error scenarios and responses:**

| Error Condition | HTTP Status | Error Code | Action |
|----------------|-------------|------------|--------|
| No auth provided | 401 | `UNAUTHORIZED` | Reject request |
| Invalid token format | 401 | `INVALID_TOKEN` | Reject request |
| Token expired | 401 | `TOKEN_EXPIRED` | Reject, pod retries with fresh token |
| TokenReview API failed | 503 | `AUTH_UNAVAILABLE` | Reject (fail closed) |
| Token not authenticated | 401 | `UNAUTHORIZED` | Reject request |
| Policy denied | 403 | `POLICY_DENIED` | Reject with policy reason |

**Fail-closed security:**
- If TokenReview API is unavailable → reject request
- If token validation fails → reject request
- No fallback to weaker auth when K8s auth fails
- Session secret auth is separate mode, not fallback

**Error response format:**

```json
{
  "error": "INVALID_TOKEN",
  "message": "Failed to validate Kubernetes service account token: token has expired",
  "request_id": "abc123",
  "hint": "Ensure pod is using current projected service account token"
}
```

---

## Deployment Architecture

### DaemonSet Model

**Why DaemonSet:**
- Aligns with "node-local HTTP proxy" vision
- One proxy instance per node
- Low latency (localhost access)
- Horizontal scaling with cluster size
- No need for Service load balancing

**Pod network access:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
spec:
  containers:
  - name: app
    env:
    - name: HTTP_PROXY
      value: "http://$(NODE_IP):8088"
    - name: NODE_IP
      valueFrom:
        fieldRef:
          fieldPath: status.hostIP
```

**DaemonSet manifest structure:**

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: veilwarden
  namespace: veilwarden-system
spec:
  selector:
    matchLabels:
      app: veilwarden
  template:
    spec:
      serviceAccountName: veilwarden
      hostNetwork: true  # Access node IP
      containers:
      - name: veilwarden
        image: veilwarden:latest
        ports:
        - containerPort: 8088
          hostPort: 8088
        volumeMounts:
        - name: config
          mountPath: /etc/veilwarden
      volumes:
      - name: config
        configMap:
          name: veilwarden-config
```

### Network Policies

**Ingress to veilwarden:**
- Allow from all pods in cluster (acts as egress proxy)
- Deny external traffic (only pod-to-proxy allowed)

**Egress from veilwarden:**
- Allow to Kubernetes API server (for TokenReview)
- Allow to upstream APIs (proxied destinations)
- Allow to Doppler API (for secret fetching)

---

## Policy Integration

### OPA Policy Examples

**Allow based on namespace:**

```rego
package veilwarden.authz

import rego.v1

default allow := false

# Production namespace can access production APIs
allow if {
    input.k8s_namespace == "production"
    input.upstream_host == "api.stripe.com"
}

# Development namespace restricted to test APIs
allow if {
    input.k8s_namespace == "development"
    startswith(input.upstream_host, "sandbox.")
}
```

**Allow based on service account:**

```rego
# CI/CD service account can deploy
allow if {
    input.k8s_service_account == "ci-deployer"
    input.method == "POST"
    input.upstream_host == "api.github.com"
}

# Read-only service account
allow if {
    input.k8s_service_account == "readonly-app"
    input.method == "GET"
}
```

**Allow based on pod naming convention:**

```rego
# Pods matching pattern can access specific APIs
allow if {
    regex.match("^backend-api-.*", input.k8s_pod_name)
    input.upstream_host == "api.internal.com"
}
```

**Deny dangerous operations:**

```rego
# Block DELETE from non-admin namespaces
deny if {
    input.method == "DELETE"
    input.k8s_namespace != "admin"
}

# Prevent production namespace from accessing development APIs
deny if {
    input.k8s_namespace == "production"
    contains(input.upstream_host, "dev.")
}
```

---

## Security Considerations

### Token Security

**Best practices:**
1. **Use bound tokens** (default in K8s 1.22+)
   - Time-limited (automatic rotation)
   - Audience-restricted
   - Pod-bound (can't be reused from different pod)

2. **Validate audience** in TokenReview request
   - Prevents token forwarding attacks
   - Ensures token intended for veilwarden

3. **Check expiration** via TokenReview API
   - Kubernetes handles this automatically
   - No stale token acceptance

4. **Fail closed** on validation errors
   - If API server unavailable → reject
   - If token invalid → reject
   - No degraded security mode

### RBAC Security

**Principle of least privilege:**
- Veilwarden ServiceAccount only needs `tokenreviews.create`
- No need for broader cluster-admin permissions
- Namespace-scoped where possible

**Audit logging:**
- Log all authentication attempts
- Include namespace, service account, pod name
- Track policy decisions for compliance

### Network Security

**Token transmission:**
- Tokens sent in `Authorization: Bearer` header
- HTTPS required for external traffic
- In-cluster traffic can use HTTP (network policies isolate)

**Token storage:**
- Never log full token values
- Truncate in error messages: `Bearer tok...xyz`
- No persistent storage of tokens

---

## Testing Strategy

### Unit Tests

**Focus:** JWT parsing, identity extraction, configuration

**Test cases:**
- Parse valid JWT token claims
- Extract namespace, service account, pod name
- Handle malformed tokens
- Validate claim structure
- Test dual-mode auth selection
- Configuration auto-detection

**Example:**

```go
func TestExtractK8sIdentity(t *testing.T) {
    token := createTestToken(t, map[string]interface{}{
        "kubernetes.io": map[string]interface{}{
            "namespace": "production",
            "serviceaccount": map[string]interface{}{
                "name": "my-app",
            },
            "pod": map[string]interface{}{
                "name": "my-app-abc123",
            },
        },
    })

    identity, err := parseK8sToken(token)
    assert.NoError(t, err)
    assert.Equal(t, "production", identity.K8sNamespace())
    assert.Equal(t, "my-app", identity.K8sServiceAccount())
}
```

### Integration Tests (EnvTest)

**Focus:** TokenReview API interaction, RBAC validation

**Setup:**
- Use `sigs.k8s.io/controller-runtime/pkg/envtest`
- Spin up real API server + etcd
- Create test ServiceAccounts
- Issue test tokens via TokenRequest API

**Test cases:**
- Valid token → authenticated
- Expired token → rejected
- Invalid signature → rejected
- Missing RBAC permissions → error
- TokenReview API response parsing

**Example:**

```go
func TestTokenReviewIntegration(t *testing.T) {
    testEnv := &envtest.Environment{}
    cfg, err := testEnv.Start()
    require.NoError(t, err)
    defer testEnv.Stop()

    client := kubernetes.NewForConfigOrDie(cfg)

    // Create test ServiceAccount
    sa := &corev1.ServiceAccount{...}
    client.CoreV1().ServiceAccounts("default").Create(ctx, sa, metav1.CreateOptions{})

    // Request token
    tokenRequest := &authenticationv1.TokenRequest{...}
    result, err := client.CoreV1().ServiceAccounts("default").CreateToken(ctx, "test-sa", tokenRequest, metav1.CreateOptions{})

    // Test validation
    validator := NewK8sTokenValidator(client)
    identity, err := validator.Validate(ctx, result.Status.Token)
    assert.NoError(t, err)
    assert.Equal(t, "default", identity.K8sNamespace())
}
```

### E2E Tests (kind)

**Focus:** Full pod lifecycle, real token projection

**Setup:**
- Create kind cluster
- Deploy veilwarden DaemonSet
- Deploy test workload pod
- Configure networking

**Test scenarios:**
1. **Successful authentication**
   - Pod with SA token → veilwarden → upstream (allowed)
   - Verify identity extracted correctly
   - Verify policy evaluation

2. **Policy enforcement**
   - Pod from allowed namespace → allow
   - Pod from denied namespace → deny (403)
   - Verify error responses

3. **Token lifecycle**
   - Initial token → success
   - Wait for rotation → success with new token
   - Expired token → rejection

4. **Backwards compatibility**
   - Session secret auth still works
   - K8s auth doesn't break legacy mode

**Optional (CI/CD only):**
- Run with `RUN_K8S_E2E=true` environment variable
- Skip by default (too slow for local dev)

---

## Future Enhancements

### Phase 2: Pod Metadata Enrichment

**Motivation:** Enable label-based policy decisions

**Approach:**
1. Extract namespace + pod name from token
2. Query Kubernetes API: `GET /api/v1/namespaces/{ns}/pods/{name}`
3. Cache pod metadata (labels, annotations) with TTL
4. Add to PolicyInput

**Configuration:**

```yaml
kubernetes:
  pod_metadata:
    enabled: true
    cache_ttl: 5m
    fields:
      - labels
      - annotations
```

**PolicyInput additions:**

```go
type PolicyInput struct {
    // ...
    K8sPodLabels      map[string]string
    K8sPodAnnotations map[string]string
}
```

**Policy example:**

```rego
# Allow pods with specific label
allow if {
    input.k8s_pod_labels["app.kubernetes.io/component"] == "api-gateway"
    input.upstream_host == "backend.internal"
}
```

### Phase 3: JWKS-Based Local Validation

**Motivation:** Reduce latency, eliminate API dependency

**Approach:**
1. Fetch JWKS from `<api-server>/openid/v1/jwks`
2. Cache public keys with TTL
3. Validate JWT signature locally (RS256)
4. Verify claims (exp, aud, iss, nbf)

**Configuration:**

```yaml
kubernetes:
  validate_method: jwks  # instead of tokenreview
  jwks_cache_ttl: 1h
  jwks_refresh_interval: 15m
```

**Benefits:**
- No network call per request
- Sub-millisecond validation
- Offline operation possible

**Tradeoffs:**
- More complex implementation
- Must handle key rotation
- Manual claim verification

### Phase 4: Multi-Cluster Support

**Motivation:** Proxy for workloads across multiple clusters

**Approach:**
1. Configure multiple API server endpoints
2. Detect cluster from token issuer claim
3. Route TokenReview to correct cluster
4. Support different RBAC per cluster

**Configuration:**

```yaml
kubernetes:
  clusters:
    - name: prod-us-east
      api_server: https://prod-us-east.example.com

    - name: prod-eu-west
      api_server: https://prod-eu-west.example.com
```

### Phase 5: Custom Token Audiences

**Motivation:** Stronger isolation, prevent token reuse

**Approach:**
1. Configure veilwarden-specific audience
2. Workloads request tokens with custom audience via TokenRequest API
3. Reject tokens without correct audience

**Configuration:**

```yaml
kubernetes:
  audience: "veilwarden.example.com"
  require_audience: true
```

**Workload manifest:**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    env:
    - name: VEILWARDEN_TOKEN
      valueFrom:
        serviceAccountToken:
          audience: "veilwarden.example.com"
          expirationSeconds: 3600
```

---

## Migration Path

### For New Deployments

1. Deploy veilwarden DaemonSet with K8s auth enabled
2. Configure workload pods with SA token projection
3. Set `Authorization: Bearer` header in HTTP proxy config
4. Define OPA policies for namespace/SA access control

### For Existing Deployments

1. **Phase 1:** Deploy updated veilwarden with dual-mode auth
   - Session secret auth continues to work
   - No workload changes required

2. **Phase 2:** Gradually migrate workloads
   - Update pod specs to use `Authorization: Bearer` header
   - Test with small subset of pods
   - Monitor authentication metrics

3. **Phase 3:** Deprecate session secret (optional)
   - After full migration, consider removing session secret support
   - Or keep for local development use cases

**No breaking changes required** - dual-mode authentication ensures smooth migration.

---

## Monitoring & Observability

### Metrics

**Authentication metrics:**
- `veilwarden_auth_attempts_total{method, result}` - Auth attempts by method and result
- `veilwarden_k8s_tokenreview_duration_seconds` - TokenReview API latency
- `veilwarden_k8s_tokenreview_errors_total{reason}` - TokenReview failures by reason

**Identity metrics:**
- `veilwarden_requests_total{namespace, service_account}` - Requests by K8s identity
- `veilwarden_policy_decisions_total{namespace, decision}` - Policy results by namespace

### Logging

**Structured log fields:**

```json
{
  "level": "info",
  "msg": "authenticated request",
  "auth_method": "kubernetes",
  "k8s_namespace": "production",
  "k8s_service_account": "my-app",
  "k8s_pod_name": "my-app-abc123",
  "request_id": "xyz789"
}
```

**Security events to log:**
- Authentication failures (with truncated token)
- Policy denials (with full context)
- TokenReview API errors
- RBAC permission errors

---

## Open Questions

*To be resolved during implementation:*

1. **Audience configuration:**
   - Use default `https://kubernetes.default.svc` or custom?
   - Make configurable or hardcode?

2. **Token caching:**
   - Should validated tokens be cached to reduce TokenReview calls?
   - Cache key: token hash? (security implications)
   - TTL: match token expiration?

3. **ServiceAccount lookup:**
   - Should we query SA object for additional metadata?
   - Use case: SA labels, annotations for policy

4. **Namespace isolation:**
   - Should veilwarden be deployable per-namespace?
   - Or always cluster-scoped?

5. **Token refresh:**
   - Do we need to handle token refresh for long-lived connections?
   - Or assume short-lived HTTP requests only?

---

## References

- [Kubernetes Service Account Token Projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#serviceaccount-token-volume-projection)
- [TokenReview API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/)
- [Kubernetes OIDC Discovery KEP](https://github.com/kubernetes/enhancements/blob/master/keps/sig-auth/1393-oidc-discovery/README.md)
- [Bound Service Account Tokens KEP](https://github.com/kubernetes/enhancements/blob/master/keps/sig-auth/1205-bound-service-account-tokens/README.md)
- [HashiCorp Vault K8s Auth](https://github.com/hashicorp/vault-plugin-auth-kubernetes) - Reference implementation
- [client-go](https://github.com/kubernetes/client-go) - Kubernetes Go client library
- [EnvTest](https://book.kubebuilder.io/reference/envtest.html) - Kubernetes integration testing

---

## Appendix: Implementation Checklist

- [ ] Add k8s.io dependencies to go.mod
- [ ] Create k8s_auth.go (TokenReview validation)
- [ ] Create k8s_identity.go (identity extraction)
- [ ] Create k8s_client.go (Kubernetes client setup)
- [ ] Update server.go (dual-mode authenticate)
- [ ] Update policy.go (add K8s PolicyInput fields)
- [ ] Update config.go (K8s configuration)
- [ ] Write unit tests (token parsing, identity extraction)
- [ ] Write integration tests (EnvTest TokenReview)
- [ ] Write E2E tests (kind, optional)
- [ ] Create deployment manifests (DaemonSet, RBAC, etc.)
- [ ] Update README.md
- [ ] Write quickstart guide
- [ ] Add policy examples
- [ ] Document RBAC requirements
