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

func TestE2EPolicyBehavior(t *testing.T) {
	// Create temp dir with exact policy from E2E test
	tmpDir := t.TempDir()
	policy := `package veilwarden.authz
import rego.v1
default allow := false
allow if { input.method == "CONNECT" }
allow if { input.method == "GET"; input.path == "/get" }
allow if { input.method == "POST"; input.path == "/post" }
allow if { input.method == "GET"; input.path == "/health" }
allow if { input.method == "GET"; startswith(input.path, "/api/") }
`
	err := os.WriteFile(filepath.Join(tmpDir, "policy.rego"), []byte(policy), 0644)
	require.NoError(t, err)

	ctx := context.Background()
	engine, err := New(ctx, tmpDir, "veilwarden/authz/allow")
	require.NoError(t, err)

	tests := []struct {
		name   string
		method string
		path   string
		expect bool
	}{
		{"GET /get should be allowed", "GET", "/get", true},
		{"GET /headers should be DENIED", "GET", "/headers", false},
		{"POST /post should be allowed", "POST", "/post", true},
		{"GET /health should be allowed", "GET", "/health", true},
		{"GET /api/test should be allowed", "GET", "/api/test", true},
		{"POST /headers should be DENIED", "POST", "/headers", false},
		{"DELETE /anything should be DENIED", "DELETE", "/anything", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := &proxy.PolicyInput{
				Method:       tc.method,
				Path:         tc.path,
				UpstreamHost: "postman-echo.com",
				Timestamp:    time.Now(),
			}
			decision, err := engine.Decide(ctx, input)
			require.NoError(t, err)
			assert.Equal(t, tc.expect, decision.Allowed,
				"Expected allowed=%v, got allowed=%v, reason=%s",
				tc.expect, decision.Allowed, decision.Reason)
		})
	}
}
