package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

const (
	sessionHeader   = "X-Session-Secret"
	upstreamHeader  = "X-Upstream-Host"
	requestIDHeader = "X-Request-Id"
)

type route struct {
	upstreamHost        string
	upstreamScheme      string
	secretID            string
	headerName          string
	headerValueTemplate string
}

type secretStore interface {
	Get(ctx context.Context, id string) (string, error)
}

type configSecretStore struct {
	secrets map[string]string
}

func (s *configSecretStore) Get(_ context.Context, id string) (string, error) {
	val, ok := s.secrets[id]
	if !ok {
		return "", fmt.Errorf("secret %q not found", id)
	}
	return val, nil
}

type proxyServer struct {
	sessionSecret    string
	routes           map[string]route
	secretStore      secretStore
	httpClient       *http.Client
	logger           *slog.Logger
	tracer           trace.Tracer
	requestCounter   metric.Int64Counter
	requestDuration  metric.Float64Histogram
	errorCounter     metric.Int64Counter
	upstreamDuration metric.Float64Histogram
	policyEngine     PolicyEngine
	policyDecisions  metric.Int64Counter
	userID           string
	userEmail        string
	userOrg          string
}

func newProxyServer(routes map[string]route, sessionSecret string, store secretStore, logger *slog.Logger, policyEngine PolicyEngine, userID, userEmail, userOrg string) *proxyServer {
	if store == nil {
		store = &configSecretStore{secrets: map[string]string{}}
	}
	if logger == nil {
		logger = slog.Default()
	}
	if policyEngine == nil {
		// Default to allow-all policy for backwards compatibility
		policyEngine = newConfigPolicyEngine(policyConfig{Enabled: false, DefaultAllow: true})
	}

	// Initialize OTEL tracer and metrics
	tracer := otel.Tracer(serviceName)
	meter := otel.Meter(serviceName)

	// Create metrics (ignore errors as they're optional)
	requestCounter, _ := meter.Int64Counter("veilwarden.requests.total",
		metric.WithDescription("Total number of proxy requests"))
	requestDuration, _ := meter.Float64Histogram("veilwarden.request.duration",
		metric.WithDescription("Duration of proxy requests in seconds"),
		metric.WithUnit("s"))
	errorCounter, _ := meter.Int64Counter("veilwarden.errors.total",
		metric.WithDescription("Total number of errors by error code"))
	upstreamDuration, _ := meter.Float64Histogram("veilwarden.upstream.duration",
		metric.WithDescription("Duration of upstream requests in seconds"),
		metric.WithUnit("s"))
	policyDecisions, _ := meter.Int64Counter("veilwarden.policy.decisions.total",
		metric.WithDescription("Total number of policy decisions by result"))

	return &proxyServer{
		sessionSecret: sessionSecret,
		routes:        routes,
		secretStore:   store,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		logger:           logger,
		tracer:           tracer,
		requestCounter:   requestCounter,
		requestDuration:  requestDuration,
		errorCounter:     errorCounter,
		upstreamDuration: upstreamDuration,
		policyEngine:     policyEngine,
		policyDecisions:  policyDecisions,
		userID:           userID,
		userEmail:        userEmail,
		userOrg:          userOrg,
	}
}

func (s *proxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Use client-provided request ID if present, otherwise generate new one
	reqID := strings.TrimSpace(r.Header.Get(requestIDHeader))
	if reqID == "" {
		reqID = newRequestID()
	}
	w.Header().Set(requestIDHeader, reqID)

	// Start OTEL span
	ctx, span := s.tracer.Start(r.Context(), "proxy.request",
		trace.WithAttributes(
			attribute.String("request.id", reqID),
			attribute.String("http.method", r.Method),
			attribute.String("http.path", r.URL.Path),
		),
	)
	defer span.End()

	// Record request counter
	s.requestCounter.Add(ctx, 1)

	if err := s.authenticate(r.Header); err != nil {
		s.recordError(ctx, "UNAUTHORIZED", reqID)
		s.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error(), reqID)
		span.SetStatus(codes.Error, "authentication failed")
		s.recordDuration(ctx, startTime)
		return
	}

	// Extract agent ID for policy context (optional header)
	agentID := strings.TrimSpace(r.Header.Get("X-Agent-Id"))

	hostHeader := strings.TrimSpace(r.Header.Get(upstreamHeader))

	// Policy decision point: Check if request is allowed before processing
	policyInput := PolicyInput{
		Method:       r.Method,
		Path:         r.URL.Path,
		Query:        r.URL.RawQuery,
		UpstreamHost: hostHeader,
		AgentID:      agentID,
		UserID:       s.userID,
		UserEmail:    s.userEmail,
		UserOrg:      s.userOrg,
		RequestID:    reqID,
		Timestamp:    time.Now(),
	}

	policyDecision, err := s.policyEngine.Decide(ctx, policyInput)
	if err != nil {
		s.recordError(ctx, "POLICY_ERROR", reqID)
		s.writeError(w, http.StatusInternalServerError, "POLICY_ERROR",
			fmt.Sprintf("Policy evaluation failed: %v", err), reqID)
		span.SetStatus(codes.Error, "policy error")
		s.recordDuration(ctx, startTime)
		return
	}

	// Record policy decision metrics
	decisionLabel := "allow"
	if !policyDecision.Allowed {
		decisionLabel = "deny"
	}
	s.policyDecisions.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("decision", decisionLabel),
			attribute.String("reason", policyDecision.Reason),
			attribute.String("agent_id", agentID),
		))

	// Add policy context to span
	span.SetAttributes(
		attribute.String("policy.decision", decisionLabel),
		attribute.String("policy.reason", policyDecision.Reason),
		attribute.String("agent.id", agentID),
	)

	// Log policy decision
	if policyDecision.Allowed {
		s.logger.Info("policy allowed request",
			"request_id", reqID,
			"decision", decisionLabel,
			"reason", policyDecision.Reason,
			"agent_id", agentID,
			"upstream_host", hostHeader)
	} else {
		s.logger.Warn("policy denied request",
			"request_id", reqID,
			"decision", decisionLabel,
			"reason", policyDecision.Reason,
			"agent_id", agentID,
			"upstream_host", hostHeader)
	}

	// If policy denies the request, return 403
	if !policyDecision.Allowed {
		s.recordError(ctx, "POLICY_DENIED", reqID)
		s.writeError(w, http.StatusForbidden, "POLICY_DENIED",
			fmt.Sprintf("Policy denied request: %s. Contact your administrator to review access policies.", policyDecision.Reason), reqID)
		span.SetStatus(codes.Error, "policy denied")
		s.recordDuration(ctx, startTime)
		return
	}
	if hostHeader == "" {
		s.recordError(ctx, "MISSING_HOST", reqID)
		s.writeError(w, http.StatusBadRequest, "MISSING_HOST",
			fmt.Sprintf("Missing upstream host: add header '%s: <host>' to specify the target API (e.g., '%s: api.github.com')", upstreamHeader, upstreamHeader), reqID)
		span.SetStatus(codes.Error, "missing host header")
		s.recordDuration(ctx, startTime)
		return
	}
	route, ok := s.routes[strings.ToLower(hostHeader)]
	if !ok {
		configured := make([]string, 0, len(s.routes))
		for host := range s.routes {
			configured = append(configured, host)
		}
		s.recordError(ctx, "HOST_NOT_ALLOWED", reqID)
		s.writeError(w, http.StatusForbidden, "HOST_NOT_ALLOWED",
			fmt.Sprintf("Host '%s' not configured: check your veilwarden.yaml config file. Configured hosts: %v", hostHeader, configured), reqID)
		span.SetStatus(codes.Error, "host not allowed")
		s.recordDuration(ctx, startTime)
		return
	}

	span.SetAttributes(attribute.String("upstream.host", route.upstreamHost))

	secretValue, err := s.secretStore.Get(ctx, route.secretID)
	if err != nil {
		msg := fmt.Sprintf("Failed to retrieve secret '%s': %v. Check that the secret exists in your Doppler project/config and that the Doppler token has read access", route.secretID, err)
		s.recordError(ctx, "SECRET_ERROR", reqID)
		s.writeError(w, http.StatusBadGateway, "SECRET_ERROR", msg, reqID)
		span.SetStatus(codes.Error, "secret retrieval failed")
		s.recordDuration(ctx, startTime)
		return
	}
	span.SetAttributes(attribute.String("secret.id", route.secretID))

	targetURL, err := buildUpstreamURL(route, r.URL)
	if err != nil {
		s.recordError(ctx, "INVALID_PATH", reqID)
		s.writeError(w, http.StatusBadRequest, "INVALID_PATH", err.Error(), reqID)
		span.SetStatus(codes.Error, "invalid path")
		s.recordDuration(ctx, startTime)
		return
	}

	upstreamReq, err := http.NewRequestWithContext(ctx, r.Method, targetURL, r.Body)
	if err != nil {
		msg := fmt.Sprintf("Failed to build upstream request to %s: %v", targetURL, err)
		s.recordError(ctx, "UPSTREAM_BUILD_ERROR", reqID)
		s.writeError(w, http.StatusInternalServerError, "UPSTREAM_BUILD_ERROR", msg, reqID)
		span.SetStatus(codes.Error, "upstream build error")
		s.recordDuration(ctx, startTime)
		return
	}

	copyHeaders(upstreamReq.Header, r.Header)
	upstreamReq.Header.Set(route.headerName, strings.ReplaceAll(route.headerValueTemplate, "{{secret}}", secretValue))
	upstreamReq.Header.Del(sessionHeader)
	upstreamReq.Header.Del(upstreamHeader)
	upstreamReq.Host = route.upstreamHost

	// Trace upstream request
	upstreamStart := time.Now()
	resp, err := s.httpClient.Do(upstreamReq)
	upstreamDuration := time.Since(upstreamStart).Seconds()
	s.upstreamDuration.Record(ctx, upstreamDuration,
		metric.WithAttributes(
			attribute.String("upstream.host", route.upstreamHost),
		))

	if err != nil {
		msg := fmt.Sprintf("Failed to connect to upstream %s: %v. Verify the host is accessible and the upstream_scheme in config is correct (http vs https)", route.upstreamHost, err)
		s.recordError(ctx, "UPSTREAM_ERROR", reqID)
		s.writeError(w, http.StatusBadGateway, "UPSTREAM_ERROR", msg, reqID)
		span.SetStatus(codes.Error, "upstream connection failed")
		s.recordDuration(ctx, startTime)
		return
	}
	defer resp.Body.Close()

	span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		s.logger.Error("failed to copy response body",
			"request_id", reqID,
			"error", err)
	}

	span.SetStatus(codes.Ok, "request completed")
	s.recordDuration(ctx, startTime)
	s.logger.Info("request completed",
		"request_id", reqID,
		"upstream", route.upstreamHost,
		"method", r.Method,
		"status", resp.StatusCode)
}

func (s *proxyServer) authenticate(h http.Header) error {
	secret := strings.TrimSpace(h.Get(sessionHeader))
	if secret == "" {
		return fmt.Errorf("missing session secret: add header '%s: <your-session-secret>' to your request (get secret from VEILWARDEN_SESSION_SECRET environment variable)", sessionHeader)
	}
	if secret != s.sessionSecret {
		return fmt.Errorf("invalid session secret: the provided session secret does not match. Verify VEILWARDEN_SESSION_SECRET matches the value used to start the proxy")
	}
	return nil
}

func buildUpstreamURL(rt route, in *url.URL) (string, error) {
	path := in.EscapedPath()
	if path == "" {
		path = "/"
	}
	target := url.URL{
		Scheme:   rt.upstreamScheme,
		Host:     rt.upstreamHost,
		Path:     path,
		RawQuery: in.RawQuery,
	}
	return target.String(), nil
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		if shouldSkipHeader(key) {
			continue
		}
		copied := make([]string, len(values))
		copy(copied, values)
		dst[key] = copied
	}
}

var hopHeaders = map[string]struct{}{
	"Connection":          {},
	"Proxy-Connection":    {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
	sessionHeader:         {},
	upstreamHeader:        {},
	requestIDHeader:       {},
}

func shouldSkipHeader(name string) bool {
	_, ok := hopHeaders[http.CanonicalHeaderKey(name)]
	return ok
}

type errorResponse struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func (s *proxyServer) writeError(w http.ResponseWriter, status int, code, message, requestID string) {
	writeJSONError(w, status, code, message, requestID)
	s.logger.Error("request failed",
		"request_id", requestID,
		"error_code", code,
		"status", status,
		"message", message)
}

func writeJSONError(w http.ResponseWriter, status int, code, message, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{
		Error:     code,
		Message:   message,
		RequestID: requestID,
	})
}

func newRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func (s *proxyServer) recordError(ctx context.Context, errorCode, requestID string) {
	s.errorCounter.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("error.code", errorCode),
			attribute.String("request.id", requestID),
		))
}

func (s *proxyServer) recordDuration(ctx context.Context, startTime time.Time) {
	duration := time.Since(startTime).Seconds()
	s.requestDuration.Record(ctx, duration)
}
