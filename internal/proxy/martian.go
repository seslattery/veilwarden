package proxy

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/martian/v3"
	"github.com/google/martian/v3/fifo"
	martianlog "github.com/google/martian/v3/log"
	"github.com/google/martian/v3/mitm"
)

// Context key for policy blocking
type policyBlockedKeyType struct{}

var policyBlockedKey = policyBlockedKeyType{}

// policyBlockedError is stored in context when policy denies a request
type policyBlockedError struct {
	reason string
}

// ErrPolicyBlocked is returned when a request is blocked by policy
var ErrPolicyBlocked = errors.New("blocked by policy")

// policyEnforcingRoundTripper wraps http.RoundTripper to enforce policy decisions.
// This is necessary because martian converts modifier errors to warning headers
// rather than actually blocking requests. By checking policy in the RoundTripper,
// we can return an error that actually prevents the request from being forwarded.
type policyEnforcingRoundTripper struct {
	wrapped http.RoundTripper
	logger  *slog.Logger
}

func (rt *policyEnforcingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Check if policy blocked this request
	if blocked, ok := req.Context().Value(policyBlockedKey).(*policyBlockedError); ok && blocked != nil {
		rt.logger.Warn("blocking request due to policy denial",
			"host", req.URL.Host,
			"path", req.URL.Path,
			"reason", blocked.reason)
		// Return a synthetic 403 Forbidden response instead of an error.
		// Returning an error would cause martian to send a 502 Bad Gateway,
		// which doesn't convey the policy denial semantically.
		body := fmt.Sprintf(`{"error":"forbidden","reason":%q}`, blocked.reason)
		return &http.Response{
			StatusCode:    http.StatusForbidden,
			Status:        "403 Forbidden",
			Proto:         req.Proto,
			ProtoMajor:    req.ProtoMajor,
			ProtoMinor:    req.ProtoMinor,
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
			Header: http.Header{
				"Content-Type":           []string{"application/json"},
				"X-Veilwarden-Blocked":   []string{"policy"},
				"X-Veilwarden-Reason":    []string{blocked.reason},
			},
			Request: req,
		}, nil
	}

	// Debug logging to diagnose DNS issues after sleep/wake.
	// The [::]:443 error indicates DNS resolution returning empty results.
	rt.logger.Debug("round trip starting",
		"scheme", req.URL.Scheme,
		"host", req.URL.Host,
		"path", req.URL.Path,
		"req_host_header", req.Host)

	resp, err := rt.wrapped.RoundTrip(req)
	if err != nil {
		// Log detailed error info for DNS/dial failures
		rt.logger.Debug("round trip failed",
			"error", err.Error(),
			"host", req.URL.Host,
			"scheme", req.URL.Scheme)
	}
	return resp, err
}

const (
	// MaxPolicyBodySize is the maximum request body size (in bytes) that will be read
	// for policy evaluation. This prevents DoS attacks via large request bodies.
	// Default: 1MB - sufficient for most API requests
	MaxPolicyBodySize = 1 * 1024 * 1024 // 1 MB

	// Connection pool settings to prevent hangs after system sleep/wake.
	// See: https://github.com/golang/go/issues/29308
	//
	// After system sleep, cached TCP connections become stale but the transport
	// doesn't know until it tries to use them. Aggressive timeouts and keepalive
	// settings help detect and recover from this condition quickly.
	idleConnTimeout    = 10 * time.Second // Close idle connections quickly
	tcpKeepAlive       = 5 * time.Second  // Detect dead connections faster
	tlsHandshakeTimeout = 10 * time.Second
	responseHeaderTimeout = 30 * time.Second
)

// filteredMartianLogger wraps slog to filter out benign connection errors from martian.
// Errors like "broken pipe" and "connection reset by peer" are normal during client
// disconnects and are demoted to debug level to reduce log noise.
type filteredMartianLogger struct {
	logger *slog.Logger
}

func (l *filteredMartianLogger) Infof(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	// Filter noisy martian internal messages that are logged for every HTTPS request
	if strings.Contains(msg, "forcing HTTPS inside secure session") {
		l.logger.Debug(msg)
		return
	}
	l.logger.Info(msg)
}

func (l *filteredMartianLogger) Debugf(format string, args ...interface{}) {
	l.logger.Debug(fmt.Sprintf(format, args...))
}

func (l *filteredMartianLogger) Errorf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if strings.Contains(msg, "broken pipe") || strings.Contains(msg, "connection reset by peer") {
		l.logger.Debug(msg)
		return
	}
	l.logger.Error(msg)
}

// isValidHeaderValue validates that a string is safe to use as an HTTP header value.
// It checks for control characters (especially newlines) that could enable header injection.
// Per RFC 7230, header field values must be visible ASCII characters or spaces/tabs.
func isValidHeaderValue(value string) bool {
	// Explicit check for newline sequences (header injection) - defense in depth
	if strings.ContainsAny(value, "\r\n") {
		return false
	}

	for _, r := range value {
		// Allow: visible ASCII (0x21-0x7E), space (0x20), tab (0x09)
		// Reject: control characters including CR (0x0D), LF (0x0A)
		if r < 0x20 || r > 0x7E {
			if r != 0x09 { // Allow tab
				return false
			}
		}
	}
	return true
}

// MartianConfig holds configuration for the Martian MITM proxy.
type MartianConfig struct {
	SessionID      string
	CACert         *x509.Certificate
	CAKey          *rsa.PrivateKey
	Routes         map[string]Route
	SecretStore    SecretStore
	PolicyEngine   PolicyEngine
	Logger         *slog.Logger
	TimeoutSeconds int // Proxy timeout in seconds. Default: 300 (5 minutes)
	// Note: Martian doesn't expose idle timeout configuration. Connection cleanup
	// is handled by the graceful shutdown mechanism in Close() which completes
	// in-flight requests before closing connections.
}

// MartianProxy wraps a Martian proxy with VeilWarden configuration.
type MartianProxy struct {
	proxy        *martian.Proxy
	transport    *http.Transport // Custom transport for connection management
	sessionID    string
	policyEngine PolicyEngine
	secretStore  SecretStore
	routes       map[string]Route
	logger       *slog.Logger
}

// dnsRetryDialer wraps a net.Dialer to retry DNS resolution on failure.
// This handles macOS mDNSResponder issues after sleep/wake where DNS
// queries can fail transiently with empty results (causing dial tcp [::]:443 errors).
type dnsRetryDialer struct {
	dialer     *net.Dialer
	resolver   *net.Resolver
	logger     *slog.Logger
	maxRetries int
	retryDelay time.Duration
}

// DialContext dials with DNS pre-resolution and retry logic.
// If DNS resolution fails, it retries a few times before giving up.
func (d *dnsRetryDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// If we can't split, fall back to standard dial
		return d.dialer.DialContext(ctx, network, address)
	}

	// Skip DNS pre-resolution for IP addresses
	if ip := net.ParseIP(host); ip != nil {
		return d.dialer.DialContext(ctx, network, address)
	}

	// Pre-resolve DNS with retry logic to handle mDNSResponder issues after sleep
	var addrs []string
	var lastErr error
	for attempt := 0; attempt <= d.maxRetries; attempt++ {
		if attempt > 0 {
			if d.logger != nil {
				d.logger.Debug("retrying DNS resolution",
					"host", host,
					"attempt", attempt,
					"last_error", lastErr)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(d.retryDelay):
			}
		}

		addrs, lastErr = d.resolver.LookupHost(ctx, host)
		if lastErr == nil && len(addrs) > 0 {
			break
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("DNS returned no addresses for %s", host)
		}
	}

	if lastErr != nil || len(addrs) == 0 {
		if d.logger != nil {
			d.logger.Warn("DNS resolution failed after retries",
				"host", host,
				"error", lastErr,
				"retries", d.maxRetries)
		}
		errMsg := "DNS resolution failed"
		if lastErr != nil {
			errMsg = lastErr.Error()
		}
		return nil, fmt.Errorf("DNS lookup for %s: %s (possible mDNSResponder issue after sleep - try flushing DNS cache)", host, errMsg)
	}

	// Try each resolved address
	for _, addr := range addrs {
		target := net.JoinHostPort(addr, port)
		conn, err := d.dialer.DialContext(ctx, network, target)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	return nil, lastErr
}

// newResilientTransportWithDialer creates an HTTP transport configured to handle
// system sleep/wake gracefully. After sleep, TCP connections become stale
// but Go's connection pool doesn't detect this until requests fail.
//
// This transport uses aggressive settings to minimize hang time:
// - Short idle connection timeout (connections expire quickly when unused)
// - Aggressive TCP keepalive (detects dead connections faster)
// - Disabled connection pooling (each request gets a fresh connection)
// - DNS pre-resolution with retry to handle mDNSResponder issues after sleep
//
// The dialer should be shared with proxy.SetDial() to ensure CONNECT tunnels
// and HTTP requests both benefit from DNS retry logic.
func newResilientTransportWithDialer(logger *slog.Logger, dnsDialer *dnsRetryDialer) *http.Transport {
	return &http.Transport{
		// Disable connection pooling entirely to prevent stale connection issues.
		// This means each request creates a new TCP connection, but eliminates
		// the class of bugs where pooled connections become stale after sleep.
		DisableKeepAlives: true,

		// Even with DisableKeepAlives, set short timeouts as defense-in-depth
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,

		// Use custom dialer with DNS retry logic for sleep/wake resilience
		DialContext: dnsDialer.DialContext,

		// Limit concurrent connections to prevent resource exhaustion
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     100,
	}
}

// NewMartianProxy creates a new Martian MITM proxy.
func NewMartianProxy(cfg *MartianConfig) (*MartianProxy, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Configure martian's internal logger to filter benign connection errors
	martianlog.SetLogger(&filteredMartianLogger{logger: cfg.Logger})

	// Create Martian proxy
	proxy := martian.NewProxy()

	// Setup MITM if CA cert provided
	if cfg.CACert != nil && cfg.CAKey != nil {
		mc, err := mitm.NewConfig(cfg.CACert, cfg.CAKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create MITM config: %w", err)
		}

		mc.SetValidity(1 * time.Hour)
		mc.SetOrganization("VeilWarden MITM")

		proxy.SetMITM(mc)
	}

	// Set proxy timeout (default 5 minutes for streaming support)
	timeout := 300 * time.Second
	if cfg.TimeoutSeconds > 0 {
		timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
	}
	proxy.SetTimeout(timeout)

	// Create DNS retry dialer for mDNSResponder resilience after sleep/wake.
	// This must be set on BOTH the proxy (for CONNECT tunnels) AND the transport
	// (for HTTP requests) since they use different dial paths.
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: tcpKeepAlive,
	}
	dnsDialer := &dnsRetryDialer{
		dialer:     dialer,
		resolver:   net.DefaultResolver,
		logger:     cfg.Logger,
		maxRetries: 3,             // Increased from 2 - mDNSResponder can be slow
		retryDelay: 200 * time.Millisecond, // Increased from 100ms for more reliability
	}

	// Set dialer on proxy for CONNECT tunnels (HTTPS connections)
	proxy.SetDial(func(network, addr string) (net.Conn, error) {
		return dnsDialer.DialContext(context.Background(), network, addr)
	})

	// Create a resilient transport that handles system sleep/wake gracefully.
	// This replaces http.DefaultTransport to prevent stale connection hangs.
	transport := newResilientTransportWithDialer(cfg.Logger, dnsDialer)

	// Set the transport as the base RoundTripper
	var rt http.RoundTripper = transport

	// Wrap with policy enforcement if configured
	// This is necessary because martian converts modifier errors to warning headers
	// rather than actually blocking requests
	if cfg.PolicyEngine != nil {
		rt = &policyEnforcingRoundTripper{
			wrapped: rt,
			logger:  cfg.Logger,
		}
	}
	proxy.SetRoundTripper(rt)

	s := &MartianProxy{
		proxy:        proxy,
		transport:    transport,
		sessionID:    cfg.SessionID,
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
func (s *MartianProxy) registerModifiers() {
	stack := fifo.NewGroup()

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

// Serve starts the proxy server on the given listener.
func (s *MartianProxy) Serve(listener net.Listener) error {
	s.logger.Info("martian proxy listening", "addr", listener.Addr().String())
	return s.proxy.Serve(listener)
}

// Close gracefully shuts down the proxy, allowing in-flight requests to complete.
// It signals the proxy to stop accepting new connections and waits for existing
// connections to finish. This prevents goroutine leaks and ensures clean shutdown.
func (s *MartianProxy) Close() {
	s.logger.Info("shutting down martian proxy")

	// Close idle connections first to speed up shutdown.
	// This is especially important after system sleep when connections may be stale.
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}

	s.proxy.Close()
}

// policyModifier enforces policies on requests.
type policyModifier struct {
	policyEngine PolicyEngine
	sessionID    string
	logger       *slog.Logger
}

// ModifyRequest enforces policy on the request.
func (m *policyModifier) ModifyRequest(req *http.Request) error {
	ctx := req.Context()

	// Skip policy enforcement for CONNECT requests - they just establish tunnels
	// The actual HTTP request inside the tunnel will be evaluated separately
	if req.Method == http.MethodConnect {
		m.logger.Debug("skipping policy for CONNECT tunnel", "host", req.URL.Host)
		return nil
	}

	// Read and buffer request body for policy evaluation
	// Use LimitReader to prevent DoS attacks via large request bodies
	var bodyBytes []byte
	if req.Body != nil {
		limitedReader := io.LimitReader(req.Body, MaxPolicyBodySize)
		var err error
		bodyBytes, err = io.ReadAll(limitedReader)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}

		// Check if we hit the limit - if so, warn and truncate
		if len(bodyBytes) == MaxPolicyBodySize {
			m.logger.Warn("request body truncated for policy evaluation",
				"limit_bytes", MaxPolicyBodySize,
				"host", req.URL.Host,
				"path", req.URL.Path)
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
		// Store the block reason in context for the RoundTripper to enforce
		// We can't just return an error here because martian converts modifier
		// errors to warning headers rather than blocking the request
		blocked := &policyBlockedError{reason: decision.Reason}
		*req = *req.WithContext(context.WithValue(ctx, policyBlockedKey, blocked))
		return nil // Don't return error - let RoundTripper handle the block
	}

	m.logger.Debug("policy allowed request",
		"host", host,
		"path", req.URL.Path)

	return nil
}

// secretInjectorModifier injects API credentials from secret store.
type secretInjectorModifier struct {
	routes      map[string]Route
	secretStore SecretStore
	logger      *slog.Logger
}

// ModifyRequest injects the appropriate secret into the request headers.
func (m *secretInjectorModifier) ModifyRequest(req *http.Request) error {
	ctx := req.Context()

	// Skip secret injection for CONNECT requests - they just establish tunnels
	// The actual HTTP request inside the tunnel will have secrets injected
	if req.Method == http.MethodConnect {
		m.logger.Debug("skipping secret injection for CONNECT tunnel", "host", req.URL.Host)
		return nil
	}

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
	secret, err := m.secretStore.Get(ctx, route.SecretID)
	if err != nil {
		m.logger.Error("failed to fetch secret",
			"secret_id", route.SecretID,
			"host", host,
			"error", err)
		return fmt.Errorf("failed to fetch secret %s: %w", route.SecretID, err)
	}

	// Validate secret value to prevent header injection attacks
	if !isValidHeaderValue(secret) {
		m.logger.Error("secret contains invalid characters for HTTP header",
			"secret_id", route.SecretID,
			"host", host)
		return fmt.Errorf("secret %s contains invalid characters for HTTP header", route.SecretID)
	}

	// Inject secret into header
	headerValue := strings.ReplaceAll(route.HeaderValueTemplate, "{{secret}}", secret)

	// Validate final header value as well (in case template contains invalid chars)
	if !isValidHeaderValue(headerValue) {
		m.logger.Error("header value contains invalid characters",
			"secret_id", route.SecretID,
			"header", route.HeaderName,
			"host", host)
		return fmt.Errorf("header value for %s contains invalid characters", route.HeaderName)
	}

	req.Header.Set(route.HeaderName, headerValue)

	m.logger.Info("injected secret",
		"host", host,
		"header", route.HeaderName,
		"secret_id", route.SecretID)

	return nil
}
