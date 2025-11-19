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
