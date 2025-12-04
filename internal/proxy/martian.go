package proxy

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/martian/v3"
	"github.com/google/martian/v3/fifo"
	"github.com/google/martian/v3/mitm"
)

const (
	// MaxPolicyBodySize is the maximum request body size (in bytes) that will be read
	// for policy evaluation. This prevents DoS attacks via large request bodies.
	// Default: 1MB - sufficient for most API requests
	MaxPolicyBodySize = 1 * 1024 * 1024 // 1 MB
)

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
	SessionID    string
	CACert       *x509.Certificate
	CAKey        *rsa.PrivateKey
	Routes       map[string]Route
	SecretStore  SecretStore
	PolicyEngine PolicyEngine
	Logger       *slog.Logger
}

// MartianProxy wraps a Martian proxy with VeilWarden configuration.
type MartianProxy struct {
	proxy        *martian.Proxy
	sessionID    string
	policyEngine PolicyEngine
	secretStore  SecretStore
	routes       map[string]Route
	logger       *slog.Logger
}

// NewMartianProxy creates a new Martian MITM proxy.
func NewMartianProxy(cfg *MartianConfig) (*MartianProxy, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

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

	proxy.SetTimeout(30 * time.Second)

	s := &MartianProxy{
		proxy:        proxy,
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
		return fmt.Errorf("forbidden by policy: %s", decision.Reason)
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
