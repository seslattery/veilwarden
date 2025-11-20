package main

import (
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMartianProxyServer_BasicMITM(t *testing.T) {
	// Generate ephemeral CA for test
	sessionID := "test-session"

	// Mock upstream server
	requestReceived := false
	mockUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestReceived = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockUpstream.Close()

	// Create proxy config
	cfg := &MartianProxyConfig{
		SessionID:   sessionID,
		RequireAuth: false,
	}

	proxy, err := NewMartianProxyServer(cfg)
	require.NoError(t, err)

	// Start proxy on random port
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer proxyListener.Close()

	proxyURL := "http://" + proxyListener.Addr().String()

	go proxy.Serve(proxyListener)

	// Create HTTP client configured to use proxy
	proxyURLParsed, _ := url.Parse(proxyURL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURLParsed),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // For testing only
			},
		},
	}

	// Make request through proxy
	resp, err := client.Get(mockUpstream.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, requestReceived, "request should reach upstream server")
}

func TestPolicyModifier_AllowedRequest(t *testing.T) {
	// Create allow-all policy engine
	policyEngine := newConfigPolicyEngine(policyConfig{
		Enabled:      true,
		DefaultAllow: true,
	})

	modifier := &policyModifier{
		policyEngine: policyEngine,
		sessionID:    "test-session",
		logger:       slog.Default(),
	}

	req := httptest.NewRequest("GET", "https://api.openai.com/v1/models", nil)

	err := modifier.ModifyRequest(req)
	assert.NoError(t, err, "allow-all policy should allow request")
}

func TestPolicyModifier_DeniedRequest(t *testing.T) {
	// Create deny-all policy engine
	policyEngine := newConfigPolicyEngine(policyConfig{
		Enabled:      true,
		DefaultAllow: false,
	})

	modifier := &policyModifier{
		policyEngine: policyEngine,
		sessionID:    "test-session",
		logger:       slog.Default(),
	}

	req := httptest.NewRequest("GET", "https://api.openai.com/v1/models", nil)

	err := modifier.ModifyRequest(req)
	assert.Error(t, err, "deny-all policy should deny request")
	assert.Contains(t, err.Error(), "forbidden by policy")
}

func TestSecretInjectorModifier_InjectsSecret(t *testing.T) {
	// Create mock secret store
	secretStore := &configSecretStore{
		secrets: map[string]string{
			"OPENAI_API_KEY": "sk-test-secret-12345",
		},
	}

	// Create routes
	routes := map[string]route{
		"api.openai.com": {
			upstreamHost:        "api.openai.com",
			secretID:            "OPENAI_API_KEY",
			headerName:          "Authorization",
			headerValueTemplate: "Bearer {{secret}}",
		},
	}

	modifier := &secretInjectorModifier{
		routes:      routes,
		secretStore: secretStore,
		logger:      slog.Default(),
	}

	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", nil)

	err := modifier.ModifyRequest(req)
	assert.NoError(t, err)

	// Verify secret was injected
	assert.Equal(t, "Bearer sk-test-secret-12345", req.Header.Get("Authorization"))
}

func TestSecretInjectorModifier_NoRouteConfigured(t *testing.T) {
	modifier := &secretInjectorModifier{
		routes:      map[string]route{},
		secretStore: &configSecretStore{secrets: map[string]string{}},
		logger:      slog.Default(),
	}

	req := httptest.NewRequest("GET", "https://unknown.example.com/test", nil)

	err := modifier.ModifyRequest(req)
	assert.NoError(t, err, "should pass through without error")
	assert.Empty(t, req.Header.Get("Authorization"), "should not inject header")
}

func TestMartianProxyServer_E2E_SecretInjectionAndPolicy(t *testing.T) {
	// Setup: Create ephemeral CA
	sessionID := "e2e-test-session"

	// Mock upstream HTTP server (not HTTPS) that verifies secret was injected
	var receivedAuth string
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockUpstream.Close()

	// Extract host from mock upstream URL
	upstreamURL, _ := url.Parse(mockUpstream.URL)
	upstreamHost := upstreamURL.Host
	if h, _, err := net.SplitHostPort(upstreamHost); err == nil {
		upstreamHost = h
	}

	// Configure proxy with routes and secrets
	routes := map[string]route{
		upstreamHost: {
			upstreamHost:        upstreamHost,
			secretID:            "TEST_SECRET",
			headerName:          "Authorization",
			headerValueTemplate: "Bearer {{secret}}",
		},
	}

	secretStore := &configSecretStore{
		secrets: map[string]string{
			"TEST_SECRET": "sk-e2e-test-secret",
		},
	}

	policyEngine := newConfigPolicyEngine(policyConfig{
		Enabled:      true,
		DefaultAllow: true,
	})

	// Create and start proxy
	cfg := &MartianProxyConfig{
		SessionID:    sessionID,
		RequireAuth:  false,
		Routes:       routes,
		SecretStore:  secretStore,
		PolicyEngine: policyEngine,
	}

	proxy, err := NewMartianProxyServer(cfg)
	require.NoError(t, err)

	proxyListener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer proxyListener.Close()

	go proxy.Serve(proxyListener)

	// Make request through proxy (plain HTTP)
	proxyURL, _ := url.Parse("http://" + proxyListener.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get(mockUpstream.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "Bearer sk-e2e-test-secret", receivedAuth, "secret should be injected")
}
