package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/seslattery/veilwarden/internal/policy/opa"
	"github.com/seslattery/veilwarden/internal/proxy"
)

// TestPolicyEnforcementBlocking tests that the proxy ACTUALLY blocks requests
// when policy denies them. This is a critical test because the original bug
// was that martian converts modifier errors to warning headers instead of
// blocking requests - requests would succeed with a warning header instead
// of failing.
func TestPolicyEnforcementBlocking(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	// Start a local backend server
	backend := startBackendServer(t)
	defer backend.Close()

	// Create a policy that denies POST to /blocked paths
	policyDir := t.TempDir()
	policyFile := filepath.Join(policyDir, "policy.rego")
	policyContent := `package veil

import rego.v1

default allow := false

# Allow CONNECT for proxy connections
allow if {
    input.method == "CONNECT"
}

# Allow GET requests to any path
allow if {
    input.method == "GET"
}

# Block POST requests to /blocked path
deny contains msg if {
    input.method == "POST"
    startswith(input.path, "/blocked")
    msg := "POST to /blocked is not allowed by policy"
}

# Allow POST to /allowed path
allow if {
    input.method == "POST"
    startswith(input.path, "/allowed")
}
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)

	// Create OPA engine
	ctx := context.Background()
	engine, err := opa.New(ctx, policyDir, "veil/allow")
	require.NoError(t, err)

	// Start proxy
	proxyListener, proxyAddr := startProxyWithPolicy(t, engine)
	defer proxyListener.Close()

	// Create HTTP client that uses the proxy
	proxyURL, err := url.Parse("http://" + proxyAddr)
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	backendURL := "http://" + backend.Addr

	t.Run("POST to blocked path should fail", func(t *testing.T) {
		// This is the critical test - POST to /blocked should FAIL, not succeed
		// with a warning header
		req, err := http.NewRequest("POST", backendURL+"/blocked/endpoint", strings.NewReader("test data"))
		require.NoError(t, err)

		resp, err := client.Do(req)

		// The request should either fail with an error OR return a non-2xx status
		// It should NOT succeed with a 2xx status and a warning header
		if err != nil {
			// Good - the request failed as expected
			t.Logf("Request correctly failed with error: %v", err)
			assert.Contains(t, err.Error(), "blocked")
			return
		}
		defer resp.Body.Close()

		// If we get here, check that it's not a successful response
		body, _ := io.ReadAll(resp.Body)
		t.Logf("Response status: %d, body: %s", resp.StatusCode, string(body))

		// SECURITY CHECK: If backend received the request, that's a failure
		if resp.Header.Get("X-Backend-Received") == "true" {
			t.Fatal("SECURITY BUG: Blocked request reached backend!")
		}

		// The response should NOT be successful
		assert.True(t, resp.StatusCode >= 400, "Blocked request should not return success status, got %d", resp.StatusCode)
	})

	t.Run("GET requests should be allowed", func(t *testing.T) {
		req, err := http.NewRequest("GET", backendURL+"/get", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err, "GET request should succeed")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "GET should return 200")
		assert.Equal(t, "true", resp.Header.Get("X-Backend-Received"), "Request should reach backend")
	})

	t.Run("POST to allowed path should succeed", func(t *testing.T) {
		req, err := http.NewRequest("POST", backendURL+"/allowed/endpoint", strings.NewReader("test data"))
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err, "POST to allowed path should not be blocked by proxy")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "POST to allowed path should return 200")
		assert.Equal(t, "true", resp.Header.Get("X-Backend-Received"), "Request should reach backend")
	})
}

// TestPolicyEnforcementHTTPMethods tests that policy enforcement works for all HTTP methods
func TestPolicyEnforcementHTTPMethods(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	backend := startBackendServer(t)
	defer backend.Close()

	// Create a policy that only allows GET
	policyDir := t.TempDir()
	policyFile := filepath.Join(policyDir, "policy.rego")
	policyContent := `package veil

import rego.v1

default allow := false

# Allow CONNECT for proxy
allow if {
    input.method == "CONNECT"
}

# Only allow GET requests
allow if {
    input.method == "GET"
}

deny contains msg if {
    input.method != "GET"
    input.method != "CONNECT"
    msg := sprintf("Only GET allowed, got %s", [input.method])
}
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)

	ctx := context.Background()
	engine, err := opa.New(ctx, policyDir, "veil/allow")
	require.NoError(t, err)

	proxyListener, proxyAddr := startProxyWithPolicy(t, engine)
	defer proxyListener.Close()

	proxyURL, err := url.Parse("http://" + proxyAddr)
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	backendURL := "http://" + backend.Addr

	methods := []struct {
		method      string
		shouldBlock bool
	}{
		{"GET", false},
		{"POST", true},
		{"PUT", true},
		{"DELETE", true},
		{"PATCH", true},
	}

	for _, tc := range methods {
		t.Run(tc.method, func(t *testing.T) {
			var body io.Reader
			if tc.method != "GET" && tc.method != "DELETE" {
				body = strings.NewReader("test data")
			}

			req, err := http.NewRequest(tc.method, backendURL+"/anything", body)
			require.NoError(t, err)

			resp, err := client.Do(req)

			if tc.shouldBlock {
				// Request should fail or return error status
				if err != nil {
					t.Logf("%s correctly blocked with error: %v", tc.method, err)
					return
				}
				defer resp.Body.Close()

				// SECURITY CHECK: Backend should not receive blocked requests
				if resp.Header.Get("X-Backend-Received") == "true" {
					t.Fatalf("SECURITY BUG: Blocked %s request reached backend!", tc.method)
				}

				assert.True(t, resp.StatusCode >= 400,
					"%s should be blocked, got status %d", tc.method, resp.StatusCode)
			} else {
				// Request should succeed
				require.NoError(t, err, "%s should not be blocked", tc.method)
				defer resp.Body.Close()
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				t.Logf("%s returned status: %d", tc.method, resp.StatusCode)
			}
		})
	}
}

// TestPolicyEnforcementDenyAllByDefault tests that requests are blocked when no allow rule matches
func TestPolicyEnforcementDenyAllByDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	backend := startBackendServer(t)
	defer backend.Close()

	// Create a policy that only allows CONNECT (required for proxy) and nothing else
	policyDir := t.TempDir()
	policyFile := filepath.Join(policyDir, "policy.rego")
	policyContent := `package veil

import rego.v1

default allow := false

# Only allow CONNECT for proxy connections
allow if {
    input.method == "CONNECT"
}

# Everything else is denied by default (allow = false)
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)

	ctx := context.Background()
	engine, err := opa.New(ctx, policyDir, "veil/allow")
	require.NoError(t, err)

	proxyListener, proxyAddr := startProxyWithPolicy(t, engine)
	defer proxyListener.Close()

	proxyURL, err := url.Parse("http://" + proxyAddr)
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	backendURL := "http://" + backend.Addr

	t.Run("GET should be blocked by default", func(t *testing.T) {
		req, err := http.NewRequest("GET", backendURL+"/get", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		if err != nil {
			t.Logf("GET correctly blocked with error: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.Header.Get("X-Backend-Received") == "true" {
			t.Fatal("SECURITY BUG: Blocked GET request reached backend!")
		}

		assert.True(t, resp.StatusCode >= 400,
			"GET should be blocked, got status %d", resp.StatusCode)
	})

	t.Run("POST should be blocked by default", func(t *testing.T) {
		req, err := http.NewRequest("POST", backendURL+"/post", strings.NewReader("data"))
		require.NoError(t, err)

		resp, err := client.Do(req)
		if err != nil {
			t.Logf("POST correctly blocked with error: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.Header.Get("X-Backend-Received") == "true" {
			t.Fatal("SECURITY BUG: Blocked POST request reached backend!")
		}

		assert.True(t, resp.StatusCode >= 400,
			"POST should be blocked, got status %d", resp.StatusCode)
	})
}

// TestPolicyEnforcementPathAndMethodCombinations tests complex policy combinations
func TestPolicyEnforcementPathAndMethodCombinations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	backend := startBackendServer(t)
	defer backend.Close()

	policyDir := t.TempDir()
	policyFile := filepath.Join(policyDir, "policy.rego")
	policyContent := `package veil

import rego.v1

default allow := false

# Allow CONNECT
allow if {
    input.method == "CONNECT"
}

# Allow GET to any path
allow if {
    input.method == "GET"
}

# Allow POST only to /api paths
allow if {
    input.method == "POST"
    startswith(input.path, "/api/")
}

# Block POST to /admin paths
deny contains msg if {
    input.method == "POST"
    startswith(input.path, "/admin/")
    msg := "POST to admin paths is blocked"
}

# Block DELETE entirely
deny contains msg if {
    input.method == "DELETE"
    msg := "DELETE requests are blocked"
}
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)

	ctx := context.Background()
	engine, err := opa.New(ctx, policyDir, "veil/allow")
	require.NoError(t, err)

	proxyListener, proxyAddr := startProxyWithPolicy(t, engine)
	defer proxyListener.Close()

	proxyURL, err := url.Parse("http://" + proxyAddr)
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	backendURL := "http://" + backend.Addr

	testCases := []struct {
		name        string
		method      string
		path        string
		shouldBlock bool
	}{
		{"GET to root", "GET", "/", false},
		{"GET to admin", "GET", "/admin/users", false},
		{"POST to api", "POST", "/api/data", false},
		{"POST to admin", "POST", "/admin/delete", true},
		{"POST to root", "POST", "/other", true}, // Not in /api/
		{"DELETE to api", "DELETE", "/api/resource", true},
		{"DELETE to root", "DELETE", "/", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var body io.Reader
			if tc.method == "POST" {
				body = strings.NewReader("test data")
			}

			req, err := http.NewRequest(tc.method, backendURL+tc.path, body)
			require.NoError(t, err)

			resp, err := client.Do(req)

			if tc.shouldBlock {
				if err != nil {
					t.Logf("%s %s correctly blocked with error: %v", tc.method, tc.path, err)
					return
				}
				defer resp.Body.Close()

				if resp.Header.Get("X-Backend-Received") == "true" {
					t.Fatalf("SECURITY BUG: Blocked %s %s request reached backend!", tc.method, tc.path)
				}

				assert.True(t, resp.StatusCode >= 400,
					"%s %s should be blocked, got status %d", tc.method, tc.path, resp.StatusCode)
			} else {
				require.NoError(t, err, "%s %s should not be blocked", tc.method, tc.path)
				defer resp.Body.Close()
				assert.Equal(t, http.StatusOK, resp.StatusCode)
			}
		})
	}
}

// Helper: Start a simple backend server that marks all received requests
type testBackend struct {
	Addr   string
	server *http.Server
}

func startBackendServer(t *testing.T) *testBackend {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := listener.Addr().String()

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mark that backend received the request - this is the critical check
			w.Header().Set("X-Backend-Received", "true")
			w.Header().Set("X-Request-Method", r.Method)
			w.Header().Set("X-Request-Path", r.URL.Path)
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Backend received %s %s", r.Method, r.URL.Path)
		}),
	}

	go func() {
		if err := server.Serve(listener); err != http.ErrServerClosed {
			t.Logf("Backend server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(50 * time.Millisecond)

	return &testBackend{
		Addr:   addr,
		server: server,
	}
}

func (b *testBackend) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	b.server.Shutdown(ctx)
}

// Helper: Start proxy with a policy engine
func startProxyWithPolicy(t *testing.T, engine proxy.PolicyEngine) (net.Listener, string) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := listener.Addr().String()

	cfg := &proxy.MartianConfig{
		SessionID:    "test-session",
		PolicyEngine: engine,
	}

	p, err := proxy.NewMartianProxy(cfg)
	require.NoError(t, err)

	go func() {
		if err := p.Serve(listener); err != nil {
			t.Logf("Proxy error: %v", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	return listener, addr
}
