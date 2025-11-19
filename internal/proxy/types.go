package proxy

import (
	"context"
	"time"
)

// Route represents an upstream API route configuration.
type Route struct {
	UpstreamHost        string
	SecretID            string
	HeaderName          string
	HeaderValueTemplate string
}

// SecretStore provides access to secrets.
type SecretStore interface {
	Get(ctx context.Context, secretID string) (string, error)
}

// PolicyEngine defines the interface for making authorization decisions.
type PolicyEngine interface {
	Decide(ctx context.Context, input *PolicyInput) (PolicyDecision, error)
}

// PolicyInput contains all context needed for policy evaluation.
type PolicyInput struct {
	// Request context
	Method       string
	Path         string
	Query        string
	UpstreamHost string

	// Session context (for laptop mode)
	SessionID string

	// Resource context
	SecretID string

	// Request body for policy inspection
	Body string

	// Metadata
	RequestID string
	Timestamp time.Time
}

// PolicyDecision represents the result of a policy evaluation.
type PolicyDecision struct {
	Allowed  bool
	Reason   string
	Metadata map[string]string
}
