package allowlist

import (
	"context"
	"fmt"
	"strings"

	"github.com/gobwas/glob"
	"github.com/seslattery/veilwarden/internal/proxy"
)

// Rule defines a single allowlist entry.
type Rule struct {
	Host    string   // Required: exact or glob pattern (supports *, ?, [])
	Methods []string // Optional: nil = all methods
	Paths   []string // Optional: nil = all paths (supports *, ?, [])
}

// compiledRule is a Rule with pre-compiled glob patterns.
type compiledRule struct {
	originalHost string          // For error messages
	hostGlob     glob.Glob       // nil if compilation failed
	methods      map[string]bool // nil = all allowed
	pathGlobs    []glob.Glob     // nil = all allowed
}

// Engine implements proxy.PolicyEngine using domain allowlists.
type Engine struct {
	rules []compiledRule
}

// isGlobPattern returns true if the pattern contains glob metacharacters.
func isGlobPattern(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[]")
}

// New creates a new allowlist policy engine.
// Returns an error if any rule has an invalid glob pattern.
func New(rules []Rule) (*Engine, error) {
	compiled := make([]compiledRule, 0, len(rules))

	for i, r := range rules {
		cr := compiledRule{
			originalHost: r.Host,
		}

		// Compile host pattern (lowercase for case-insensitive matching per DNS spec)
		hostLower := strings.ToLower(r.Host)
		var hostErr error
		if isGlobPattern(hostLower) {
			cr.hostGlob, hostErr = glob.Compile(hostLower)
		} else {
			// Exact match - compile as literal
			cr.hostGlob, hostErr = glob.Compile(glob.QuoteMeta(hostLower))
		}
		if hostErr != nil {
			return nil, fmt.Errorf("rule[%d]: invalid host pattern %q: %w", i, r.Host, hostErr)
		}

		// Compile methods (uppercase)
		if len(r.Methods) > 0 {
			cr.methods = make(map[string]bool)
			for _, m := range r.Methods {
				cr.methods[strings.ToUpper(m)] = true
			}
		}

		// Compile path patterns
		if len(r.Paths) > 0 {
			cr.pathGlobs = make([]glob.Glob, 0, len(r.Paths))
			for j, p := range r.Paths {
				g, pathErr := glob.Compile(p)
				if pathErr != nil {
					return nil, fmt.Errorf("rule[%d]: invalid path pattern %q at index %d: %w", i, p, j, pathErr)
				}
				cr.pathGlobs = append(cr.pathGlobs, g)
			}
		}

		compiled = append(compiled, cr)
	}

	return &Engine{rules: compiled}, nil
}

// matchResult represents why a rule did or didn't match.
type matchResult struct {
	matched      bool
	hostMatched  bool
	methodFailed bool
	pathFailed   bool
	ruleHost     string // original host pattern for error messages
}

// Decide implements proxy.PolicyEngine.
func (e *Engine) Decide(ctx context.Context, input *proxy.PolicyInput) (proxy.PolicyDecision, error) {
	var bestPartialMatch *matchResult

	for _, rule := range e.rules {
		result := rule.matchWithReason(input)
		if result.matched {
			return proxy.PolicyDecision{
				Allowed: true,
				Reason:  fmt.Sprintf("allowed by allowlist: %s", input.UpstreamHost),
				Metadata: map[string]string{
					"engine": "allowlist",
				},
			}, nil
		}

		// Track partial matches for better error messages
		// Copy the result before taking its address to avoid capturing the loop variable
		if result.hostMatched && bestPartialMatch == nil {
			resultCopy := result
			bestPartialMatch = &resultCopy
		}
	}

	// Provide specific denial reason
	reason := fmt.Sprintf("host %s not in allowlist", input.UpstreamHost)
	if bestPartialMatch != nil {
		if bestPartialMatch.methodFailed {
			reason = fmt.Sprintf("host %s matched rule %q but method %s not allowed",
				input.UpstreamHost, bestPartialMatch.ruleHost, input.Method)
		} else if bestPartialMatch.pathFailed {
			reason = fmt.Sprintf("host %s matched rule %q but path %s not allowed",
				input.UpstreamHost, bestPartialMatch.ruleHost, input.Path)
		}
	}

	return proxy.PolicyDecision{
		Allowed: false,
		Reason:  reason,
		Metadata: map[string]string{
			"engine": "allowlist",
		},
	}, nil
}

func (r *compiledRule) matchWithReason(input *proxy.PolicyInput) matchResult {
	result := matchResult{
		ruleHost: r.originalHost,
	}

	// Check host (case-insensitive per DNS spec)
	if r.hostGlob == nil || !r.hostGlob.Match(strings.ToLower(input.UpstreamHost)) {
		return result
	}
	result.hostMatched = true

	// Check method (if restricted)
	if r.methods != nil && !r.methods[strings.ToUpper(input.Method)] {
		result.methodFailed = true
		return result
	}

	// Check path (if restricted)
	if r.pathGlobs != nil {
		pathMatched := false
		for _, pg := range r.pathGlobs {
			if pg.Match(input.Path) {
				pathMatched = true
				break
			}
		}
		if !pathMatched {
			result.pathFailed = true
			return result
		}
	}

	result.matched = true
	return result
}
