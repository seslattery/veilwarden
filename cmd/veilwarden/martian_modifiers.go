package main

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
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

// policyModifier enforces OPA policies on requests.
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
	routes      map[string]route
	secretStore secretStore
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
	secret, err := m.secretStore.Get(ctx, route.secretID)
	if err != nil {
		m.logger.Error("failed to fetch secret",
			"secret_id", route.secretID,
			"host", host,
			"error", err)
		return fmt.Errorf("failed to fetch secret %s: %w", route.secretID, err)
	}

	// Validate secret value to prevent header injection attacks
	if !isValidHeaderValue(secret) {
		m.logger.Error("secret contains invalid characters for HTTP header",
			"secret_id", route.secretID,
			"host", host)
		return fmt.Errorf("secret %s contains invalid characters for HTTP header", route.secretID)
	}

	// Inject secret into header
	headerValue := strings.ReplaceAll(route.headerValueTemplate, "{{secret}}", secret)

	// Validate final header value as well (in case template contains invalid chars)
	if !isValidHeaderValue(headerValue) {
		m.logger.Error("header value contains invalid characters",
			"secret_id", route.secretID,
			"header", route.headerName,
			"host", host)
		return fmt.Errorf("header value for %s contains invalid characters", route.headerName)
	}

	req.Header.Set(route.headerName, headerValue)

	m.logger.Info("injected secret",
		"host", host,
		"header", route.headerName,
		"secret_id", route.secretID)

	return nil
}
