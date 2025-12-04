package opa

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/seslattery/veilwarden/internal/proxy"
)

// Engine implements proxy.PolicyEngine using Open Policy Agent.
type Engine struct {
	query        rego.PreparedEvalQuery
	decisionPath string
}

// New creates a new OPA-backed policy engine.
// It loads all .rego files from the specified policy path.
func New(ctx context.Context, policyPath, decisionPath string) (*Engine, error) {
	if policyPath == "" {
		return nil, fmt.Errorf("policy_path is required for OPA engine")
	}

	// Load all .rego files from policy path
	policies, err := loadRegoFiles(policyPath)
	if err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}

	if len(policies) == 0 {
		return nil, fmt.Errorf("no .rego files found in %s", policyPath)
	}

	// Use default decision path if not provided
	if decisionPath == "" {
		decisionPath = "github.com/seslattery/veilwarden/authz/allow"
	}

	// Build the query string - convert path like "github.com/seslattery/veilwarden/authz/allow" to "data.veilwarden.authz.allow"
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

	return &Engine{
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

// Decide implements proxy.PolicyEngine using OPA policy evaluation.
func (e *Engine) Decide(ctx context.Context, input *proxy.PolicyInput) (proxy.PolicyDecision, error) {
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
		"body":          input.Body,
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
	// Add Session ID if present (laptop mode)
	if input.SessionID != "" {
		inputMap["session_id"] = input.SessionID
	}

	// Evaluate the prepared query
	results, err := e.query.Eval(ctx, rego.EvalInput(inputMap))
	if err != nil {
		return proxy.PolicyDecision{}, fmt.Errorf("OPA eval: %w", err)
	}

	// Check if we got results
	if len(results) == 0 {
		return proxy.PolicyDecision{
			Allowed: false,
			Reason:  "denied by OPA policy (no results)",
			Metadata: map[string]string{
				"engine": "opa",
			},
		}, nil
	}

	// Extract boolean result from first result
	if len(results[0].Expressions) == 0 {
		return proxy.PolicyDecision{
			Allowed: false,
			Reason:  "denied by OPA policy (no expressions)",
			Metadata: map[string]string{
				"engine": "opa",
			},
		}, nil
	}

	allowed, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return proxy.PolicyDecision{}, fmt.Errorf("OPA decision returned non-boolean: %T", results[0].Expressions[0].Value)
	}

	decision := proxy.PolicyDecision{
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
