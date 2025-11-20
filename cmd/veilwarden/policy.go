package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"veilwarden/internal/proxy"
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

// PolicyEngine is an alias for the shared policy engine interface.
type PolicyEngine = proxy.PolicyEngine

// PolicyInput is an alias for the shared policy input type.
type PolicyInput = proxy.PolicyInput

// PolicyDecision is an alias for the shared policy decision type.
type PolicyDecision = proxy.PolicyDecision

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
