package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"
)

// identity represents an authenticated entity (user or workload).
type identity interface {
	Type() string                        // "static", "kubernetes"
	Attributes() map[string]string       // All identity attributes
	PolicyInput() map[string]interface{} // OPA policy input fields
}

// staticIdentity represents static user identity from config.
type staticIdentity struct {
	userID    string
	userEmail string
	userOrg   string
}

// Type returns the identity type.
func (i *staticIdentity) Type() string {
	return "static"
}

// Attributes returns the identity attributes as a map.
func (i *staticIdentity) Attributes() map[string]string {
	return map[string]string{
		"user_id":    i.userID,
		"user_email": i.userEmail,
		"user_org":   i.userOrg,
	}
}

// PolicyInput returns the input map for policy evaluation.
func (i *staticIdentity) PolicyInput() map[string]interface{} {
	return map[string]interface{}{
		"user_id":    i.userID,
		"user_email": i.userEmail,
		"user_org":   i.userOrg,
	}
}

// PolicyEngine defines the interface for making authorization decisions.
// This abstraction allows for simple config-based policies (MVP) and future
// OPA-backed policy evaluation without changing handler logic.
type PolicyEngine interface {
	// Decide evaluates whether a request should be allowed based on the provided input.
	// Returns a PolicyDecision with the result and reasoning.
	Decide(ctx context.Context, input *PolicyInput) (PolicyDecision, error)
}

// PolicyInput contains all context needed for policy evaluation.
type PolicyInput struct {
	// Request context
	Method       string
	Path         string
	Query        string
	UpstreamHost string

	// Identity context
	AgentID   string // from X-Agent-Id header (optional)
	UserID    string // from CLI flags (Doppler context)
	UserEmail string // from CLI flags (Doppler context)
	UserOrg   string // from CLI flags (Doppler context)

	// Kubernetes identity context (for k8s workloads)
	Namespace      string // Kubernetes namespace
	ServiceAccount string // Kubernetes service account
	PodName        string // Kubernetes pod name (optional)

	// Session context (for laptop mode)
	SessionID string

	// Resource context
	SecretID string // which secret would be used (empty if route not resolved yet)

	// Request body for policy inspection (NEW)
	Body string

	// Metadata
	RequestID string
	Timestamp time.Time
}

// PolicyDecision represents the result of a policy evaluation.
type PolicyDecision struct {
	Allowed  bool              // whether the request is allowed
	Reason   string            // human-readable explanation (for logging/debugging)
	Metadata map[string]string // additional context for audit/telemetry
}

// policyConfig contains policy engine configuration.
type policyConfig struct {
	Enabled      bool   // feature flag to enable/disable policy enforcement
	DefaultAllow bool   // MVP: simple boolean decision
	Engine       string // "config" or "opa"
	PolicyPath   string // path to .rego files (for opa engine)
	DecisionPath string // OPA query path (default: veilwarden/authz/allow)
}

// configPolicyEngine is the MVP implementation that makes decisions based on
// a simple boolean configuration value. This will be replaced with OPA-backed
// implementation in the future without changing the PolicyEngine interface.
type configPolicyEngine struct {
	config policyConfig
}

// newConfigPolicyEngine creates a new config-based policy engine.
func newConfigPolicyEngine(cfg policyConfig) *configPolicyEngine {
	return &configPolicyEngine{
		config: cfg,
	}
}

// Decide implements PolicyEngine for config-based policy.
// In this MVP implementation, it simply returns allow/deny based on the
// configured default value.
func (p *configPolicyEngine) Decide(ctx context.Context, input *PolicyInput) (PolicyDecision, error) {
	// If policy is not enabled, allow all requests
	if !p.config.Enabled {
		return PolicyDecision{
			Allowed: true,
			Reason:  "policy enforcement disabled",
		}, nil
	}

	// MVP: Return the configured default decision
	decision := PolicyDecision{
		Allowed: p.config.DefaultAllow,
		Metadata: map[string]string{
			"engine": "config",
		},
	}

	if decision.Allowed {
		decision.Reason = "allowed by default policy"
	} else {
		decision.Reason = "denied by default policy"
	}

	return decision, nil
}

// buildPolicyInput constructs a policy input map from request context and identity.
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

	// Merge identity-specific fields
	for k, v := range ident.PolicyInput() {
		input[k] = v
	}

	return input
}

// generateRequestID creates a random request ID for tracking.
func generateRequestID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}
	return hex.EncodeToString(bytes)
}
