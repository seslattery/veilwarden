package proxy

import (
	"context"
)

// AllowAllPolicyEngine is a simple policy engine that allows all requests.
type AllowAllPolicyEngine struct{}

// NewAllowAllPolicyEngine creates a new allow-all policy engine.
func NewAllowAllPolicyEngine() *AllowAllPolicyEngine {
	return &AllowAllPolicyEngine{}
}

// Decide always allows requests.
func (p *AllowAllPolicyEngine) Decide(ctx context.Context, input *PolicyInput) (PolicyDecision, error) {
	return PolicyDecision{
		Allowed: true,
		Reason:  "allow-all policy",
		Metadata: map[string]string{
			"engine": "allow-all",
		},
	}, nil
}
