package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/open-policy-agent/opa/sdk"
)

// opaPolicyEngine implements PolicyEngine using Open Policy Agent.
type opaPolicyEngine struct {
	opa          *sdk.OPA
	decisionPath string
}

// newOPAPolicyEngine creates a new OPA-backed policy engine.
// It loads all .rego files from the specified policy path.
func newOPAPolicyEngine(ctx context.Context, cfg policyConfig) (*opaPolicyEngine, error) {
	if cfg.PolicyPath == "" {
		return nil, fmt.Errorf("policy_path is required for OPA engine")
	}

	// Load all .rego files from policy path
	policies, err := loadRegoFiles(cfg.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}

	if len(policies) == 0 {
		return nil, fmt.Errorf("no .rego files found in %s", cfg.PolicyPath)
	}

	// Create OPA SDK configuration
	config := []byte(`{
		"services": {},
		"bundles": {},
		"decision_logs": {
			"console": false
		}
	}`)

	// Initialize OPA SDK
	opa, err := sdk.New(ctx, sdk.Options{
		Config: bytes.NewReader(config),
		// Provide policies directly via in-memory bundle
		Ready: func(ctx context.Context) {
			// OPA is ready
		},
	})
	if err != nil {
		return nil, fmt.Errorf("initialize OPA SDK: %w", err)
	}

	// Load policies into OPA
	for path, content := range policies {
		if err := opa.InsertPolicy(ctx, path, []byte(content)); err != nil {
			opa.Stop(ctx)
			return nil, fmt.Errorf("insert policy %s: %w", path, err)
		}
	}

	decisionPath := cfg.DecisionPath
	if decisionPath == "" {
		decisionPath = "veilwarden/authz/allow"
	}

	return &opaPolicyEngine{
		opa:          opa,
		decisionPath: decisionPath,
	}, nil
}

// loadRegoFiles reads all .rego files from the specified directory.
// Returns a map of filename -> file content.
func loadRegoFiles(dir string) (map[string]string, error) {
	policies := make(map[string]string)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if filepath.Ext(entry.Name()) != ".rego" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		policies[entry.Name()] = string(content)
	}

	return policies, nil
}

// Decide implements PolicyEngine using OPA policy evaluation.
func (p *opaPolicyEngine) Decide(ctx context.Context, input PolicyInput) (PolicyDecision, error) {
	// Convert PolicyInput to map for OPA
	inputMap := map[string]interface{}{
		"method":        input.Method,
		"path":          input.Path,
		"query":         input.Query,
		"upstream_host": input.UpstreamHost,
		"agent_id":      input.AgentID,
		"user_id":       input.UserID,
		"user_email":    input.UserEmail,
		"user_org":      input.UserOrg,
		"secret_id":     input.SecretID,
		"request_id":    input.RequestID,
		"timestamp":     input.Timestamp.Format(time.RFC3339),
	}

	// Query OPA for decision
	result, err := p.opa.Decision(ctx, sdk.DecisionOptions{
		Path:  p.decisionPath,
		Input: inputMap,
	})
	if err != nil {
		return PolicyDecision{}, fmt.Errorf("OPA decision: %w", err)
	}

	// Extract boolean result
	allowed, ok := result.Result.(bool)
	if !ok {
		return PolicyDecision{}, fmt.Errorf("OPA decision returned non-boolean: %T", result.Result)
	}

	decision := PolicyDecision{
		Allowed: allowed,
		Metadata: map[string]string{
			"engine":      "opa",
			"decision_id": result.ID,
		},
	}

	if allowed {
		decision.Reason = "allowed by OPA policy"
	} else {
		decision.Reason = "denied by OPA policy"
	}

	return decision, nil
}

// Close shuts down the OPA instance.
func (p *opaPolicyEngine) Close() {
	if p.opa != nil {
		p.opa.Stop(context.Background())
	}
}
