package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMartianPolicyBlockIntegration tests that policy blocking works through
// the full martian proxy flow.
func TestMartianPolicyBlockIntegration(t *testing.T) {
	// Skip in short mode since this involves network
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Start a backend server that records what it receives
	backendReceived := false
	backend := startTestBackend(t, func(w http.ResponseWriter, r *http.Request) {
		backendReceived = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend response"))
	})
	defer backend.Close()

	// Create a policy engine that blocks /blocked path
	policyEngine := &testPolicyEngine{
		decideFunc: func(input *PolicyInput) PolicyDecision {
			t.Logf("Policy check: method=%s path=%s", input.Method, input.Path)
			if input.Path == "/blocked" {
				return PolicyDecision{Allowed: false, Reason: "path /blocked is denied"}
			}
			return PolicyDecision{Allowed: true, Reason: "allowed"}
		},
	}

	// Create the proxy
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &MartianConfig{
		SessionID:    "test-session",
		PolicyEngine: policyEngine,
		Logger:       logger,
	}

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer proxyListener.Close()

	proxy, err := NewMartianProxy(cfg)
	require.NoError(t, err)

	go proxy.Serve(proxyListener)
	time.Sleep(100 * time.Millisecond) // Give proxy time to start

	// Create client that uses the proxy
	proxyURL, _ := url.Parse("http://" + proxyListener.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	t.Run("allowed path should reach backend", func(t *testing.T) {
		backendReceived = false
		resp, err := client.Get("http://" + backend.Addr + "/allowed")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, backendReceived, "request should reach backend")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("blocked path should NOT reach backend", func(t *testing.T) {
		backendReceived = false
		resp, err := client.Get("http://" + backend.Addr + "/blocked")

		if err != nil {
			// Request failed - this is expected for blocked requests
			t.Logf("Request correctly blocked with error: %v", err)
			assert.False(t, backendReceived, "blocked request should NOT reach backend")
			return
		}
		defer resp.Body.Close()

		// If we got a response, it should be an error status
		body, _ := io.ReadAll(resp.Body)
		t.Logf("Got response: status=%d, body=%s", resp.StatusCode, string(body))
		
		assert.False(t, backendReceived, "blocked request should NOT reach backend")
		assert.True(t, resp.StatusCode >= 400, "blocked request should return error status")
	})
}

// Helper types for testing

type testPolicyEngine struct {
	decideFunc func(*PolicyInput) PolicyDecision
}

func (e *testPolicyEngine) Decide(ctx context.Context, input *PolicyInput) (PolicyDecision, error) {
	return e.decideFunc(input), nil
}

type testBackend struct {
	Addr   string
	server *http.Server
}

func startTestBackend(t *testing.T, handler http.HandlerFunc) *testBackend {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &http.Server{Handler: handler}
	go server.Serve(listener)

	return &testBackend{
		Addr:   listener.Addr().String(),
		server: server,
	}
}

func (b *testBackend) Close() {
	b.server.Close()
}
