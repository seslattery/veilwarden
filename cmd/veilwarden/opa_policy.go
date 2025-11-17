package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/rego"
)

// opaPolicyEngine implements PolicyEngine using Open Policy Agent.
type opaPolicyEngine struct {
	query        rego.PreparedEvalQuery
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

	// Build rego query with all loaded policy modules
	decisionPath := cfg.DecisionPath
	if decisionPath == "" {
		decisionPath = "veilwarden/authz/allow"
	}

	// Build the query string - convert path like "veilwarden/authz/allow" to "data.veilwarden.authz.allow"
	queryPath := "data." + strings.ReplaceAll(decisionPath, "/", ".")

	// Create rego instance with all policy modules
	regoArgs := []func(*rego.Rego){
		rego.Query(queryPath),
	}

	// Add each policy module
	for path, content := range policies {
		regoArgs = append(regoArgs, rego.Module(path, content))
	}

	// Create and prepare the query
	query, err := rego.New(regoArgs...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare rego query: %w", err)
	}

	return &opaPolicyEngine{
		query:        query,
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
		// #nosec G304 -- Policy directory comes from config, only .rego files are read
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		policies[entry.Name()] = string(content)
	}

	return policies, nil
}

// Decide implements PolicyEngine using OPA policy evaluation.
func (p *opaPolicyEngine) Decide(ctx context.Context, input *PolicyInput) (PolicyDecision, error) {
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

	// Add Kubernetes identity fields if present
	if input.Namespace != "" {
		inputMap["namespace"] = input.Namespace
	}
	if input.ServiceAccount != "" {
		inputMap["service_account"] = input.ServiceAccount
	}
	if input.PodName != "" {
		inputMap["pod_name"] = input.PodName
	}

	// Evaluate the prepared query
	results, err := p.query.Eval(ctx, rego.EvalInput(inputMap))
	if err != nil {
		return PolicyDecision{}, fmt.Errorf("OPA eval: %w", err)
	}

	// Check if we got results
	if len(results) == 0 {
		return PolicyDecision{
			Allowed: false,
			Reason:  "denied by OPA policy (no results)",
			Metadata: map[string]string{
				"engine": "opa",
			},
		}, nil
	}

	// Extract boolean result from first result
	if len(results[0].Expressions) == 0 {
		return PolicyDecision{
			Allowed: false,
			Reason:  "denied by OPA policy (no expressions)",
			Metadata: map[string]string{
				"engine": "opa",
			},
		}, nil
	}

	allowed, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return PolicyDecision{}, fmt.Errorf("OPA decision returned non-boolean: %T", results[0].Expressions[0].Value)
	}

	decision := PolicyDecision{
		Allowed: allowed,
		Metadata: map[string]string{
			"engine": "opa",
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
	// Prepared queries don't need explicit cleanup
}
