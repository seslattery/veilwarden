package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestE2EBasicProxy tests the basic proxy functionality with a real echo server
func TestE2EBasicProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Start echo server
	echoAddr := findFreePort(t)
	echoServer := startEchoServer(t, echoAddr)
	defer echoServer.Shutdown(context.Background())

	// Create temporary config
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(`
secrets:
  - id: test-secret
    value: demo-token

routes:
  - upstream_host: %s
    upstream_scheme: http
    secret_id: test-secret
    inject_header: Authorization
    header_value_template: "Bearer {{secret}}"
`, echoAddr)

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Start proxy server
	proxyAddr := findFreePort(t)
	proxyServer := startProxyServer(t, proxyServerConfig{
		listenAddr:    proxyAddr,
		configPath:    configFile,
		sessionSecret: "test-session",
	})
	defer proxyServer.Shutdown(context.Background())

	// Wait for servers to be ready
	waitForServer(t, fmt.Sprintf("http://%s", echoAddr), 5*time.Second)
	waitForServer(t, fmt.Sprintf("http://%s/healthz", proxyAddr), 5*time.Second)

	// Send request through proxy
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/test", proxyAddr), strings.NewReader("hello=world"))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("X-Session-Secret", "test-session")
	req.Header.Set("X-Upstream-Host", echoAddr)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify echo response contains injected header
	var echoResp echoResponse
	if err := json.NewDecoder(resp.Body).Decode(&echoResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	authHeader := echoResp.Headers.Get("Authorization")
	if authHeader != "Bearer demo-token" {
		t.Fatalf("expected Authorization header 'Bearer demo-token', got %q", authHeader)
	}

	if echoResp.Body != "hello=world" {
		t.Fatalf("expected body 'hello=world', got %q", echoResp.Body)
	}
}

// TestE2EDopplerIntegration tests Doppler secret retrieval
func TestE2EDopplerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Check if Doppler credentials are available
	dopplerToken := os.Getenv("DOPPLER_TOKEN")
	if dopplerToken == "" {
		t.Skip("DOPPLER_TOKEN not set, skipping Doppler integration test")
	}

	dopplerProject := getEnvOrDefault("DOPPLER_PROJECT", "veilwarden")
	dopplerConfig := getEnvOrDefault("DOPPLER_CONFIG", "dev_personal")

	// Use the same secret ID as the bash script for consistency
	secretID := "ECHO_DOPPLER_SECRET"

	// Start echo server
	echoAddr := findFreePort(t)
	echoServer := startEchoServer(t, echoAddr)
	defer echoServer.Shutdown(context.Background())

	// Create temporary config
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(`
routes:
  - upstream_host: %s
    upstream_scheme: http
    secret_id: %s
    inject_header: X-Doppler-Secret
    header_value_template: "{{secret}}"
`, echoAddr, secretID)

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Start proxy server with Doppler
	proxyAddr := findFreePort(t)
	proxyServer := startProxyServer(t, proxyServerConfig{
		listenAddr:     proxyAddr,
		configPath:     configFile,
		sessionSecret:  "test-session",
		dopplerToken:   dopplerToken,
		dopplerProject: dopplerProject,
		dopplerConfig:  dopplerConfig,
	})
	defer proxyServer.Shutdown(context.Background())

	// Wait for servers to be ready
	waitForServer(t, fmt.Sprintf("http://%s", echoAddr), 5*time.Second)
	waitForServer(t, fmt.Sprintf("http://%s/healthz", proxyAddr), 5*time.Second)

	// Send request through proxy
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/test", proxyAddr), nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("X-Session-Secret", "test-session")
	req.Header.Set("X-Upstream-Host", echoAddr)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	// Verify echo response contains injected header from Doppler
	var echoResp echoResponse
	if err := json.NewDecoder(resp.Body).Decode(&echoResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	dopplerSecret := echoResp.Headers.Get("X-Doppler-Secret")
	if dopplerSecret == "" {
		t.Fatalf("expected X-Doppler-Secret header to be set from Doppler (secret_id=%s)", secretID)
	}

	t.Logf("Successfully retrieved secret from Doppler: secret_id=%s, value=%s", secretID, dopplerSecret)
}

// TestE2EOPAIntegration tests OPA policy enforcement
func TestE2EOPAIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Start echo server
	echoAddr := findFreePort(t)
	echoServer := startEchoServer(t, echoAddr)
	defer echoServer.Shutdown(context.Background())

	// Create temporary policy
	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.Mkdir(policyDir, 0755); err != nil {
		t.Fatalf("failed to create policy dir: %v", err)
	}

	policyFile := filepath.Join(policyDir, "test.rego")
	policy := `package veilwarden.authz

import rego.v1

default allow := false

# Allow GET requests from engineering
allow if {
    input.method == "GET"
    input.user_org == "engineering"
}

# Allow POST from ci-agent
allow if {
    input.method == "POST"
    input.agent_id == "ci-agent"
}
`
	if err := os.WriteFile(policyFile, []byte(policy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	// Create config with OPA enabled
	configFile := filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(`
secrets:
  - id: test-secret
    value: demo-token

routes:
  - upstream_host: %s
    upstream_scheme: http
    secret_id: test-secret
    inject_header: Authorization
    header_value_template: "Bearer {{secret}}"

policy:
  enabled: true
  engine: opa
  policy_path: %s
  decision_path: veilwarden/authz/allow
`, echoAddr, policyDir)

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Start proxy server with OPA
	proxyAddr := findFreePort(t)
	proxyServer := startProxyServer(t, proxyServerConfig{
		listenAddr:    proxyAddr,
		configPath:    configFile,
		sessionSecret: "test-session",
		userID:        "alice",
		userEmail:     "alice@company.com",
		userOrg:       "engineering",
	})
	defer proxyServer.Shutdown(context.Background())

	// Wait for servers to be ready
	waitForServer(t, fmt.Sprintf("http://%s", echoAddr), 5*time.Second)
	waitForServer(t, fmt.Sprintf("http://%s/healthz", proxyAddr), 5*time.Second)

	client := &http.Client{Timeout: 5 * time.Second}

	// Test 1: Allowed GET request from engineering user
	t.Run("AllowedGET", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/test", proxyAddr), nil)
		req.Header.Set("X-Session-Secret", "test-session")
		req.Header.Set("X-Upstream-Host", echoAddr)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}
	})

	// Test 2: Denied POST from non ci-agent
	t.Run("DeniedPOST", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/test", proxyAddr), nil)
		req.Header.Set("X-Session-Secret", "test-session")
		req.Header.Set("X-Upstream-Host", echoAddr)
		req.Header.Set("X-Agent-Id", "unknown-agent")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected status 403, got %d", resp.StatusCode)
		}

		var errResp errorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			t.Fatalf("failed to decode error response: %v", err)
		}

		if errResp.Error != "POLICY_DENIED" {
			t.Fatalf("expected error POLICY_DENIED, got %s", errResp.Error)
		}
	})

	// Test 3: Allowed POST from ci-agent
	t.Run("AllowedPOSTFromCIAgent", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/test", proxyAddr), nil)
		req.Header.Set("X-Session-Secret", "test-session")
		req.Header.Set("X-Upstream-Host", echoAddr)
		req.Header.Set("X-Agent-Id", "ci-agent")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}
	})
}

// TestE2EDopplerWithOPA tests the full integration of Doppler + OPA
func TestE2EDopplerWithOPA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Check if Doppler credentials are available
	dopplerToken := os.Getenv("DOPPLER_TOKEN")
	if dopplerToken == "" {
		t.Skip("DOPPLER_TOKEN not set, skipping Doppler+OPA integration test")
	}

	dopplerProject := getEnvOrDefault("DOPPLER_PROJECT", "veilwarden")
	dopplerConfig := getEnvOrDefault("DOPPLER_CONFIG", "dev_personal")

	// Use the same secret ID as the bash script for consistency
	secretID := "ECHO_DOPPLER_SECRET"

	// Start echo server
	echoAddr := findFreePort(t)
	echoServer := startEchoServer(t, echoAddr)
	defer echoServer.Shutdown(context.Background())

	// Create temporary policy
	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.Mkdir(policyDir, 0755); err != nil {
		t.Fatalf("failed to create policy dir: %v", err)
	}

	policyFile := filepath.Join(policyDir, "test.rego")
	policy := `package veilwarden.authz

import rego.v1

default allow := false

# Allow requests from engineering org
allow if {
    input.user_org == "engineering"
}

# Allow ci-agent
allow if {
    input.agent_id == "ci-agent"
}
`
	if err := os.WriteFile(policyFile, []byte(policy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	// Create config with both Doppler and OPA
	configFile := filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(`
routes:
  - upstream_host: %s
    upstream_scheme: http
    secret_id: %s
    inject_header: X-Doppler-Secret
    header_value_template: "{{secret}}"

policy:
  enabled: true
  engine: opa
  policy_path: %s
  decision_path: veilwarden/authz/allow
`, echoAddr, secretID, policyDir)

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Start proxy server with both Doppler and OPA
	proxyAddr := findFreePort(t)
	proxyServer := startProxyServer(t, proxyServerConfig{
		listenAddr:     proxyAddr,
		configPath:     configFile,
		sessionSecret:  "test-session",
		dopplerToken:   dopplerToken,
		dopplerProject: dopplerProject,
		dopplerConfig:  dopplerConfig,
		userID:         "alice",
		userEmail:      "alice@company.com",
		userOrg:        "engineering",
	})
	defer proxyServer.Shutdown(context.Background())

	// Wait for servers to be ready
	waitForServer(t, fmt.Sprintf("http://%s", echoAddr), 5*time.Second)
	waitForServer(t, fmt.Sprintf("http://%s/healthz", proxyAddr), 5*time.Second)

	client := &http.Client{Timeout: 5 * time.Second}

	// Test: Allowed request gets secret from Doppler
	t.Run("AllowedWithDoppler", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/test", proxyAddr), nil)
		req.Header.Set("X-Session-Secret", "test-session")
		req.Header.Set("X-Upstream-Host", echoAddr)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		// Verify both OPA allowed the request AND Doppler secret was injected
		var echoResp echoResponse
		if err := json.NewDecoder(resp.Body).Decode(&echoResp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		dopplerSecret := echoResp.Headers.Get("X-Doppler-Secret")
		if dopplerSecret == "" {
			t.Fatalf("expected X-Doppler-Secret header to be set from Doppler (secret_id=%s)", secretID)
		}

		t.Logf("Successfully: OPA allowed + Doppler injected secret: secret_id=%s, value=%s", secretID, dopplerSecret)
	})
}

// Helper types and functions

type echoResponse struct {
	Method  string      `json:"method"`
	Path    string      `json:"path"`
	Headers http.Header `json:"headers"`
	Body    string      `json:"body"`
}

type proxyServerConfig struct {
	listenAddr     string
	configPath     string
	sessionSecret  string
	dopplerToken   string
	dopplerProject string
	dopplerConfig  string
	userID         string
	userEmail      string
	userOrg        string
}

func startEchoServer(t *testing.T, addr string) *http.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, _ := io.ReadAll(r.Body)

		resp := echoResponse{
			Method:  r.Method,
			Path:    r.URL.Path,
			Headers: r.Header.Clone(),
			Body:    string(body),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Logf("echo server error: %v", err)
		}
	}()

	return server
}

func startProxyServer(t *testing.T, cfg proxyServerConfig) *http.Server {
	t.Helper()

	// Load app config
	appCfg, err := loadAppConfig(cfg.configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Build secret store
	var store secretStore
	if cfg.dopplerToken != "" {
		store = newDopplerSecretStore(dopplerOptions{
			token:    cfg.dopplerToken,
			baseURL:  "https://api.doppler.com",
			project:  cfg.dopplerProject,
			config:   cfg.dopplerConfig,
			cacheTTL: 5 * time.Minute,
			timeout:  5 * time.Second,
		})
	} else {
		store = &configSecretStore{secrets: appCfg.secrets}
	}

	// Build policy engine
	ctx := context.Background()
	policyEngine := buildPolicyEngine(ctx, appCfg.policy)

	// Create proxy server
	proxyServer := newProxyServer(appCfg.routes, cfg.sessionSecret, store, nil, policyEngine, nil, cfg.userID, cfg.userEmail, cfg.userOrg)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/", proxyServer.handleHTTP)

	server := &http.Server{
		Addr:         cfg.listenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Logf("proxy server error: %v", err)
		}
	}()

	return server
}

func findFreePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

func waitForServer(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	client := &http.Client{Timeout: 1 * time.Second}
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("server at %s did not become ready within %v", url, timeout)
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
