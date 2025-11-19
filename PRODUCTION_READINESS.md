# Production Readiness Review: VeilWarden

## Executive Summary

VeilWarden is a secret-injecting reverse proxy designed for enterprise production use. This document analyzes production readiness gaps and provides actionable recommendations for hardening the service for large-scale, mission-critical deployments.

**Current State**: MVP-ready, suitable for low-traffic non-critical workloads
**Target State**: Production-grade data path component for enterprise SaaS applications

---

## Critical Issues (P0 - Must Fix Before Production)

### 1. **No Circuit Breakers or Bulkheads**
**Impact**: Service outage cascade, resource exhaustion
**Current**: Direct calls to Doppler/K8s APIs with basic timeouts
**Risk**:
- Doppler API outage takes down entire proxy
- Slow upstream APIs cause goroutine/memory exhaustion
- No isolation between different upstreams

**Fix**:
```go
// Add circuit breaker pattern
import "github.com/sony/gobreaker"

type resilientSecretStore struct {
    store   secretStore
    breaker *gobreaker.CircuitBreaker
}

func (r *resilientSecretStore) Get(ctx context.Context, id string) (string, error) {
    result, err := r.breaker.Execute(func() (interface{}, error) {
        return r.store.Get(ctx, id)
    })
    if err != nil {
        return "", err
    }
    return result.(string), nil
}
```

**Recommendation**:
- Circuit breakers for Doppler, K8s TokenReview, and OPA
- Per-upstream bulkheads (limit concurrent requests per destination)
- Fail-fast when circuits open

---

### 2. **No Graceful Shutdown**
**Impact**: In-flight requests dropped during deployments
**Current**: `http.Server.Shutdown()` with context, but no request draining tracking
**Risk**:
- Lost requests during rolling updates
- Incomplete secret fetches mid-request

**Fix**:
```go
// Track active requests
type proxyServer struct {
    // ... existing fields
    activeRequests sync.WaitGroup
    shuttingDown   atomic.Bool
}

func (s *proxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    if s.shuttingDown.Load() {
        http.Error(w, "Server shutting down", http.StatusServiceUnavailable)
        return
    }

    s.activeRequests.Add(1)
    defer s.activeRequests.Done()

    // ... existing handler logic
}

// In main()
func gracefulShutdown(server *http.Server, proxy *proxyServer) {
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    <-sigChan

    proxy.shuttingDown.Store(true)

    // Stop accepting new requests
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := server.Shutdown(ctx); err != nil {
        logger.Error("shutdown error", "error", err)
    }

    // Wait for in-flight requests (with timeout)
    done := make(chan struct{})
    go func() {
        proxy.activeRequests.Wait()
        close(done)
    }()

    select {
    case <-done:
        logger.Info("All requests completed")
    case <-time.After(15 * time.Second):
        logger.Warn("Forced shutdown after timeout")
    }
}
```

---

### 3. **No Rate Limiting / DoS Protection**
**Impact**: Service overwhelmed by traffic spikes or malicious actors
**Current**: Unbounded request acceptance
**Risk**:
- Memory exhaustion from too many concurrent requests
- Doppler API quota exhaustion
- K8s API server overload

**Fix**:
```go
import "golang.org/x/time/rate"

type rateLimitedServer struct {
    *proxyServer
    globalLimiter  *rate.Limiter
    perHostLimiters sync.Map // map[string]*rate.Limiter
}

func (s *rateLimitedServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // Global rate limit
    if !s.globalLimiter.Allow() {
        http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
        s.recordError(r.Context(), "RATE_LIMITED", "")
        return
    }

    // Per-upstream rate limit
    upstream := r.Header.Get(upstreamHeader)
    if limiter := s.getOrCreateLimiter(upstream); limiter != nil {
        if !limiter.Allow() {
            http.Error(w, "Per-host rate limit exceeded", http.StatusTooManyRequests)
            return
        }
    }

    s.proxyServer.ServeHTTP(w, r)
}
```

**Configuration**:
```yaml
rate_limits:
  global_rps: 10000           # Total requests/sec
  per_upstream_rps: 1000      # Per destination
  doppler_secret_fetch_rps: 100
  k8s_tokenreview_rps: 500
```

---

### 4. **Doppler Secret Store Has No Fallback/Cache Persistence**
**Impact**: Service unavailable if Doppler is down
**Current**: In-memory cache with 5-minute TTL, no persistence
**Risk**: Complete outage when Doppler API is unreachable

**Fix**: Implement persistent fallback cache

```go
type persistentSecretStore struct {
    primary   secretStore      // Doppler
    fallback  secretStore      // File-based cache
    cache     *diskCache
}

type diskCache struct {
    dir      string
    maxAge   time.Duration
    mu       sync.RWMutex
}

func (d *diskCache) Get(id string) (string, time.Time, error) {
    d.mu.RLock()
    defer d.mu.RUnlock()

    path := filepath.Join(d.dir, hashSecretID(id))
    data, err := os.ReadFile(path)
    if err != nil {
        return "", time.Time{}, err
    }

    var entry struct {
        Value     string    `json:"value"`
        FetchedAt time.Time `json:"fetched_at"`
    }
    if err := json.Unmarshal(data, &entry); err != nil {
        return "", time.Time{}, err
    }

    // Stale check
    if time.Since(entry.FetchedAt) > d.maxAge {
        return entry.Value, entry.FetchedAt, ErrStaleCache
    }

    return entry.Value, entry.FetchedAt, nil
}

func (d *diskCache) Store(id, value string) error {
    d.mu.Lock()
    defer d.mu.Unlock()

    entry := struct {
        Value     string    `json:"value"`
        FetchedAt time.Time `json:"fetched_at"`
    }{
        Value:     value,
        FetchedAt: time.Now(),
    }

    data, err := json.Marshal(entry)
    if err != nil {
        return err
    }

    path := filepath.Join(d.dir, hashSecretID(id))
    return os.WriteFile(path, data, 0600)
}

func (p *persistentSecretStore) Get(ctx context.Context, id string) (string, error) {
    // Try primary (Doppler)
    value, err := p.primary.Get(ctx, id)
    if err == nil {
        // Store in fallback cache
        _ = p.cache.Store(id, value)
        return value, nil
    }

    // Try fallback cache (allows stale)
    cachedValue, fetchedAt, cacheErr := p.cache.Get(id)
    if cacheErr == nil || cacheErr == ErrStaleCache {
        age := time.Since(fetchedAt)
        logger.Warn("using fallback cache",
            "secret_id", id,
            "age", age,
            "reason", err)
        return cachedValue, nil
    }

    return "", fmt.Errorf("primary and fallback failed: %w", err)
}
```

**Configuration**:
```yaml
doppler:
  cache_dir: /var/cache/veilwarden/secrets
  fallback_max_age: 24h  # Allow stale secrets for up to 24h during outage
  encrypt_at_rest: true
  encryption_key_path: /etc/veilwarden/cache-key
```

**Security Considerations**:
- Encrypt cached secrets at rest (AES-256-GCM)
- Use `0600` permissions on cache directory
- Hash secret IDs to avoid leaking names
- Automatic cache expiry/cleanup

---

### 5. **No Request Timeout Enforcement**
**Impact**: Hung requests consuming resources
**Current**: Client timeout honored, but no server-side enforcement
**Risk**: Slow upstreams can hold connections indefinitely

**Fix**:
```go
func (s *proxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // Enforce server-side timeout
    ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
    defer cancel()

    r = r.WithContext(ctx)

    // ... existing logic

    select {
    case <-ctx.Done():
        if ctx.Err() == context.DeadlineExceeded {
            s.recordError(ctx, "TIMEOUT", reqID)
            http.Error(w, "Request timeout", http.StatusGatewayTimeout)
        }
        return
    default:
        // Continue
    }
}
```

**Configuration**:
```yaml
timeouts:
  request_total: 30s
  upstream_dial: 5s
  upstream_response: 25s
  secret_fetch: 5s
  policy_eval: 1s
```

---

## High Priority Issues (P1 - Needed for Production Scale)

### 6. **Memory Unbounded Growth**
**Current Issues**:
- In-memory cache grows without bounds
- No request body size limits
- No connection pooling limits

**Fix**:
```go
import "github.com/hashicorp/golang-lru/v2/expirable"

// Replace map with bounded LRU cache
type dopplerSecretStore struct {
    client *http.Client
    opts   dopplerOptions
    tracer trace.Tracer
    cache  *expirable.LRU[string, string]
}

func newDopplerSecretStore(opts *dopplerOptions) *dopplerSecretStore {
    // ... existing code

    cache := expirable.NewLRU[string, string](
        1000,              // max 1000 secrets
        nil,               // no eviction callback
        opts.cacheTTL,     // 5 minute TTL
    )

    return &dopplerSecretStore{
        // ...
        cache: cache,
    }
}

// Request body size limit
func (s *proxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB max
    // ...
}

// Connection pool limits
httpClient := &http.Client{
    Timeout: 30 * time.Second,
    Transport: &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
        MaxConnsPerHost:     50,
        IdleConnTimeout:     90 * time.Second,
    },
}
```

---

### 7. **No Health Check Granularity**
**Current**: Simple `/healthz` returns 200
**Missing**:
- Readiness vs liveness distinction
- Dependency health (Doppler, K8s, OPA)
- Degraded state support

**Fix**:
```go
type healthChecker struct {
    dopplerStore secretStore
    k8sClient    *k8sClient
    opaEngine    PolicyEngine
}

func (h *healthChecker) liveness(w http.ResponseWriter, r *http.Request) {
    // Just check if service is running
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"status": "alive"})
}

func (h *healthChecker) readiness(w http.ResponseWriter, r *http.Request) {
    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()

    checks := map[string]string{
        "doppler": h.checkDoppler(ctx),
        "k8s":     h.checkK8s(ctx),
        "opa":     h.checkOPA(ctx),
    }

    allHealthy := true
    for _, status := range checks {
        if status != "healthy" {
            allHealthy = false
            break
        }
    }

    status := http.StatusOK
    if !allHealthy {
        status = http.StatusServiceUnavailable
    }

    w.WriteHeader(status)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "status": checks,
        "ready":  allHealthy,
    })
}

func (h *healthChecker) checkDoppler(ctx context.Context) string {
    // Try to fetch a canary secret or do a lightweight API check
    _, err := h.dopplerStore.Get(ctx, "health-check-canary")
    if err != nil {
        return fmt.Sprintf("unhealthy: %v", err)
    }
    return "healthy"
}
```

**Endpoints**:
- `GET /healthz` - Liveness (is process alive?)
- `GET /readyz` - Readiness (can serve traffic?)
- `GET /healthz/verbose` - Detailed health breakdown

---

### 8. **No Metrics for SLO Tracking**
**Current**: Basic request counters
**Missing**:
- Latency percentiles (p50, p95, p99)
- Error rate by type
- Secret cache hit ratio
- Upstream performance

**Fix**:
```go
// Add histogram metrics
requestDuration := meter.Float64Histogram(
    "veilwarden.request.duration",
    metric.WithDescription("Request duration in seconds"),
    metric.WithUnit("s"),
    // Add explicit buckets for SLO tracking
    metric.WithExplicitBucketBoundaries(
        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ),
)

upstreamDuration := meter.Float64Histogram(
    "veilwarden.upstream.duration",
    metric.WithDescription("Upstream request duration"),
    metric.WithExplicitBucketBoundaries(
        0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0,
    ),
)

secretFetchDuration := meter.Float64Histogram(
    "veilwarden.secret.fetch.duration",
    metric.WithDescription("Secret fetch duration from Doppler"),
)

cacheHitRate := meter.Float64Counter(
    "veilwarden.cache.hits",
    metric.WithDescription("Cache hit rate for secrets"),
)
```

**Dashboarding**:
- Request latency p99 by upstream
- Error rate by error type
- Secret fetch latency
- Cache hit ratio
- Circuit breaker state

---

### 9. **No Structured Logging Context**
**Current**: slog with basic fields
**Missing**:
- Request tracing across services
- Log sampling for high throughput
- Correlation IDs

**Fix**:
```go
// Add request context logger
func requestLogger(r *http.Request, reqID string) *slog.Logger {
    return logger.With(
        "request_id", reqID,
        "method", r.Method,
        "path", r.URL.Path,
        "remote_addr", r.RemoteAddr,
        "user_agent", r.UserAgent(),
        "trace_id", r.Header.Get("X-Trace-ID"),
    )
}

// Log sampling for high volume
type samplingLogger struct {
    logger   *slog.Logger
    sampler  *rand.Rand
    sampleRate float64
}

func (s *samplingLogger) shouldLog() bool {
    return s.sampler.Float64() < s.sampleRate
}
```

---

### 10. **No Observability for Policy Decisions**
**Current**: Basic policy allow/deny logging
**Missing**:
- Policy evaluation latency
- Which OPA rules matched/failed
- K8s workload identity audit trail

**Fix**:
```go
type auditLogger struct {
    logger *slog.Logger
}

func (a *auditLogger) logPolicyDecision(
    ctx context.Context,
    decision PolicyDecision,
    input *PolicyInput,
    duration time.Duration,
) {
    a.logger.InfoContext(ctx, "policy_decision",
        "decision", decision.Allowed,
        "reason", decision.Reason,
        "duration_ms", duration.Milliseconds(),
        "upstream", input.UpstreamHost,
        "method", input.Method,
        "user_id", input.UserID,
        "namespace", input.Namespace,
        "service_account", input.ServiceAccount,
        "agent_id", input.AgentID,
    )
}
```

---

## Medium Priority Issues (P2 - Quality of Life)

### 11. **No Dynamic Configuration Reload**
**Current**: Requires restart for config changes
**Benefit**: Zero-downtime route/policy updates

**Fix**:
```go
type configReloader struct {
    path      string
    current   atomic.Value // *appConfig
    mu        sync.RWMutex
    onChange  func(*appConfig)
}

func (c *configReloader) Watch() {
    watcher, err := fsnotify.NewWatcher()
    // ... watch for config file changes

    for {
        select {
        case event := <-watcher.Events:
            if event.Op&fsnotify.Write == fsnotify.Write {
                c.reload()
            }
        }
    }
}
```

---

### 12. **No Request Retry Logic**
**Current**: Single attempt to upstream
**Benefit**: Transient error resilience

**Fix**: Add retry with exponential backoff for idempotent requests (GET, PUT with idempotency key)

---

### 13. **No Compression Support**
**Current**: No gzip/brotli for responses
**Benefit**: Reduced bandwidth, faster responses

---

## Security Hardening

### 14. **TLS Configuration**
**Current**: HTTP only
**Required for Production**:

```go
tlsConfig := &tls.Config{
    MinVersion:               tls.VersionTLS13,
    CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
    PreferServerCipherSuites: true,
    CipherSuites: []uint16{
        tls.TLS_AES_256_GCM_SHA384,
        tls.TLS_CHACHA20_POLY1305_SHA256,
        tls.TLS_AES_128_GCM_SHA256,
    },
}

server := &http.Server{
    Addr:      ":8443",
    TLSConfig: tlsConfig,
}

server.ListenAndServeTLS("cert.pem", "key.pem")
```

**Also Add**:
- mTLS for client authentication
- Certificate rotation without downtime
- ACME/Let's Encrypt support

---

### 15. **Secret Rotation Support**
**Current**: No mechanism to detect secret rotation
**Risk**: Stale secrets in cache after rotation

**Fix**:
```go
type secretVersion struct {
    value   string
    version string
    expires time.Time
}

// Doppler API returns version metadata
// Cache invalidation on version mismatch
```

---

### 16. **Audit Logging**
**Current**: Request logs only
**Required**: Compliance audit trail

**Fix**:
```go
type auditEvent struct {
    Timestamp   time.Time
    RequestID   string
    Action      string // "secret_access", "policy_decision", "auth_attempt"
    Actor       string // user_id or service_account
    Resource    string // upstream host
    Result      string // "allowed", "denied"
    Metadata    map[string]interface{}
}

func (a *auditor) logSecretAccess(ctx context.Context, secretID string, identity identity) {
    // Write to tamper-proof audit log
}
```

---

## Deployment Architecture Recommendations

### 17. **High Availability Setup**

```yaml
# Kubernetes deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: veilwarden
spec:
  replicas: 3  # Minimum for HA
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchLabels:
                app: veilwarden
            topologyKey: kubernetes.io/hostname
      containers:
      - name: veilwarden
        image: veilwarden:latest
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: 2000m
            memory: 2Gi
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

---

### 18. **Resource Sizing**

**For 10,000 RPS with 100ms p99 latency**:

```yaml
resources:
  cpu:
    per_instance: 2 cores
    instances: 10
    total: 20 cores

  memory:
    per_instance: 2GB
    secret_cache: 500MB (1000 secrets @ 500KB each)
    connection_buffers: 500MB
    overhead: 1GB
    total: 20GB

  network:
    bandwidth: 1Gbps per instance
    connections: 10k concurrent per instance
```

**Autoscaling**:
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: veilwarden-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: veilwarden
  minReplicas: 3
  maxReplicas: 50
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "1000"
```

---

## Testing Requirements

### 19. **Load Testing**
```bash
# Benchmark with realistic traffic
hey -z 60s -c 100 -q 100 \
  -H "X-Session-Secret: test" \
  -H "X-Upstream-Host: api.stripe.com" \
  https://veilwarden.example.com/v1/charges

# Chaos testing
# - Kill Doppler during traffic
# - Inject latency to upstream
# - Trigger circuit breakers
```

### 20. **Soak Testing**
- Run 24+ hours at 50% capacity
- Monitor for memory leaks
- Check goroutine count stability

---

## Migration Path

### Phase 1: Critical Fixes (Week 1-2)
1. Circuit breakers for Doppler
2. Graceful shutdown
3. Rate limiting
4. Persistent secret cache

### Phase 2: Observability (Week 3)
5. Enhanced metrics
6. Readiness/liveness endpoints
7. Audit logging

### Phase 3: Hardening (Week 4-5)
8. TLS configuration
9. Request timeouts
10. Memory bounds

### Phase 4: Production Deploy (Week 6)
11. HA setup
12. Load testing
13. Gradual rollout (1% -> 10% -> 100%)

---

## Summary

**Before Production**: Must implement P0 items (circuit breakers, graceful shutdown, rate limiting, persistent cache, timeouts)

**For Scale**: Implement P1 items (metrics, health checks, memory bounds)

**For Enterprise**: Add P2 + Security hardening (audit logs, TLS, secret rotation)

**Estimated Effort**: 4-6 weeks for production-ready deployment

The current codebase is well-structured and has good testing coverage. The main gaps are operational resilience patterns that are standard for data path services handling production traffic.
