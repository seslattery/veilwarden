package opa

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/seslattery/veilwarden/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDevDefaultPolicy(t *testing.T) {
	// Copy only dev_default.rego to temp dir to avoid conflicts
	repoRoot := findRepoRoot(t)
	srcPolicy := filepath.Join(repoRoot, "policies", "dev_default.rego")

	policyContent, err := os.ReadFile(srcPolicy)
	require.NoError(t, err, "failed to read dev_default.rego")

	tmpDir := t.TempDir()
	err = os.WriteFile(filepath.Join(tmpDir, "dev_default.rego"), policyContent, 0644)
	require.NoError(t, err)

	ctx := context.Background()
	engine, err := New(ctx, tmpDir, "veilwarden/authz/allow")
	require.NoError(t, err, "failed to create OPA engine")

	tests := []struct {
		name    string
		input   proxy.PolicyInput
		allowed bool
		desc    string
	}{
		// LLM hosts - full access
		{
			name: "anthropic_api_post_allowed",
			input: proxy.PolicyInput{
				Method:       "POST",
				Path:         "/v1/messages",
				UpstreamHost: "api.anthropic.com",
				Body:         `{"model": "claude-3-opus"}`,
			},
			allowed: true,
			desc:    "POST to Anthropic API should be allowed",
		},
		{
			name: "openai_api_post_allowed",
			input: proxy.PolicyInput{
				Method:       "POST",
				Path:         "/v1/chat/completions",
				UpstreamHost: "api.openai.com",
				Body:         `{"model": "gpt-4"}`,
			},
			allowed: true,
			desc:    "POST to OpenAI API should be allowed",
		},

		// SCM hosts - read-only, no body
		{
			name: "github_api_get_allowed",
			input: proxy.PolicyInput{
				Method:       "GET",
				Path:         "/repos/owner/repo",
				UpstreamHost: "api.github.com",
			},
			allowed: true,
			desc:    "GET to GitHub API should be allowed",
		},
		{
			name: "github_api_post_denied",
			input: proxy.PolicyInput{
				Method:       "POST",
				Path:         "/repos/owner/repo/issues",
				UpstreamHost: "api.github.com",
				Body:         `{"title": "New issue"}`,
			},
			allowed: false,
			desc:    "POST to GitHub API should be denied (read-only)",
		},
		{
			name: "github_raw_get_allowed",
			input: proxy.PolicyInput{
				Method:       "GET",
				Path:         "/owner/repo/main/README.md",
				UpstreamHost: "raw.githubusercontent.com",
			},
			allowed: true,
			desc:    "GET to raw.githubusercontent.com should be allowed",
		},
		{
			name: "gitlab_api_get_allowed",
			input: proxy.PolicyInput{
				Method:       "GET",
				Path:         "/api/v4/projects",
				UpstreamHost: "api.gitlab.com",
			},
			allowed: true,
			desc:    "GET to GitLab API should be allowed",
		},

		// Docs/package registries - read-only
		{
			name: "pkg_go_dev_get_allowed",
			input: proxy.PolicyInput{
				Method:       "GET",
				Path:         "/github.com/stretchr/testify",
				UpstreamHost: "pkg.go.dev",
			},
			allowed: true,
			desc:    "GET to pkg.go.dev should be allowed",
		},
		{
			name: "npm_registry_get_allowed",
			input: proxy.PolicyInput{
				Method:       "GET",
				Path:         "/lodash",
				UpstreamHost: "registry.npmjs.org",
			},
			allowed: true,
			desc:    "GET to npm registry should be allowed",
		},

		// General internet - GET/HEAD only, no body
		{
			name: "random_site_get_allowed",
			input: proxy.PolicyInput{
				Method:       "GET",
				Path:         "/page",
				UpstreamHost: "example.com",
			},
			allowed: true,
			desc:    "GET to random site should be allowed",
		},
		{
			name: "random_site_post_denied",
			input: proxy.PolicyInput{
				Method:       "POST",
				Path:         "/api/data",
				UpstreamHost: "example.com",
				Body:         `{"data": "value"}`,
			},
			allowed: false,
			desc:    "POST to random site should be denied",
		},
		{
			name: "random_site_get_with_body_denied",
			input: proxy.PolicyInput{
				Method:       "GET",
				Path:         "/search",
				UpstreamHost: "some-api.com",
				Body:         `{"query": "test"}`,
			},
			allowed: false,
			desc:    "GET with body to random site should be denied",
		},
		{
			name: "head_request_allowed",
			input: proxy.PolicyInput{
				Method:       "HEAD",
				Path:         "/resource",
				UpstreamHost: "cdn.example.com",
			},
			allowed: true,
			desc:    "HEAD request should be allowed",
		},
		{
			name: "delete_request_denied",
			input: proxy.PolicyInput{
				Method:       "DELETE",
				Path:         "/resource/123",
				UpstreamHost: "api.example.com",
			},
			allowed: false,
			desc:    "DELETE request should be denied",
		},
		{
			name: "put_request_denied",
			input: proxy.PolicyInput{
				Method:       "PUT",
				Path:         "/resource/123",
				UpstreamHost: "api.example.com",
				Body:         `{"updated": true}`,
			},
			allowed: false,
			desc:    "PUT request should be denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.input.Timestamp = time.Now()
			decision, err := engine.Decide(ctx, &tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.allowed, decision.Allowed,
				"%s: expected allowed=%v, got allowed=%v (reason: %s)",
				tt.desc, tt.allowed, decision.Allowed, decision.Reason)
		})
	}
}

func TestAllowAllPolicy(t *testing.T) {
	// Create temp directory with just allow_all.rego
	tmpDir := t.TempDir()
	allowAllPolicy := `package veilwarden.authz
import rego.v1
default allow := true
`
	err := os.WriteFile(filepath.Join(tmpDir, "allow_all.rego"), []byte(allowAllPolicy), 0644)
	require.NoError(t, err)

	ctx := context.Background()
	engine, err := New(ctx, tmpDir, "veilwarden/authz/allow")
	require.NoError(t, err)

	// Test that everything is allowed
	input := &proxy.PolicyInput{
		Method:       "DELETE",
		Path:         "/sensitive/data",
		UpstreamHost: "evil.com",
		Timestamp:    time.Now(),
	}

	decision, err := engine.Decide(ctx, input)
	require.NoError(t, err)
	assert.True(t, decision.Allowed, "allow_all policy should allow everything")
}

func TestDenyAllPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	denyAllPolicy := `package veilwarden.authz
import rego.v1
default allow := false
`
	err := os.WriteFile(filepath.Join(tmpDir, "deny_all.rego"), []byte(denyAllPolicy), 0644)
	require.NoError(t, err)

	ctx := context.Background()
	engine, err := New(ctx, tmpDir, "veilwarden/authz/allow")
	require.NoError(t, err)

	input := &proxy.PolicyInput{
		Method:       "GET",
		Path:         "/",
		UpstreamHost: "localhost",
		Timestamp:    time.Now(),
	}

	decision, err := engine.Decide(ctx, input)
	require.NoError(t, err)
	assert.False(t, decision.Allowed, "deny_all policy should deny everything")
}

func TestEngineNoPolicies(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	_, err := New(ctx, tmpDir, "veilwarden/authz/allow")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no .rego files found")
}

func TestEngineInvalidPolicyPath(t *testing.T) {
	ctx := context.Background()

	_, err := New(ctx, "/nonexistent/path", "veilwarden/authz/allow")
	assert.Error(t, err)
}

// findRepoRoot walks up from current directory to find repo root
func findRepoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err)

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod)")
		}
		dir = parent
	}
}
