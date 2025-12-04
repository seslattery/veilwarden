package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestE2ESandbox tests the full sandbox functionality with all available backends.
// Requires: DOPPLER_TOKEN env var
func TestE2ESandbox(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Check prerequisites
	dopplerToken := os.Getenv("DOPPLER_TOKEN")
	if dopplerToken == "" {
		t.Skip("DOPPLER_TOKEN not set")
	}

	// Detect available backends
	backends := detectAvailableBackends()
	if len(backends) == 0 {
		t.Skip("no sandbox backends available")
	}
	t.Logf("Testing backends: %v", backends)

	// Setup shared resources
	ctx := context.Background()
	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0755); err != nil {
		t.Fatalf("failed to create policy dir: %v", err)
	}

	// Build veil binary
	veilBin := filepath.Join(tmpDir, "veil")
	repoRoot := findRepoRoot(t)
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", veilBin, "./cmd/veil")
	buildCmd.Dir = repoRoot
	buildCmd.Env = append(os.Environ(), "GOCACHE="+filepath.Join(repoRoot, ".gocache"))
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build veil: %v\n%s", err, out)
	}

	// Start echo server
	echoAddr, echoServer := startEchoServer(t)
	defer echoServer.Shutdown(ctx)
	waitForServer(t, fmt.Sprintf("http://%s/health", echoAddr), 5*time.Second)

	// Create OPA policy
	policy := `package veilwarden.authz
import rego.v1
default allow := false
allow if { input.method == "CONNECT" }
allow if { input.method == "GET"; input.path == "/get" }
allow if { input.method == "POST"; input.path == "/post" }
allow if { input.method == "GET"; input.path == "/health" }
allow if { input.method == "GET"; startswith(input.path, "/api/") }
`
	if err := os.WriteFile(filepath.Join(policyDir, "policy.rego"), []byte(policy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	// Set up Doppler secrets
	dopplerProject := getEnvOrDefault("DOPPLER_PROJECT", "veilwarden")
	dopplerConfig := getEnvOrDefault("DOPPLER_CONFIG", "dev")
	ts := time.Now().Unix()

	secretHTTPBin := fmt.Sprintf("httpbin-key-%d-%x", ts, time.Now().UnixNano()&0xFFFFFFFF)
	secretEcho := fmt.Sprintf("echo-key-%d-%x", ts, time.Now().UnixNano()&0xFFFFFFFF)
	secretBasic := fmt.Sprintf("user:pass-%d-%x", ts, time.Now().UnixNano()&0xFFFF)

	setDopplerSecrets(t, dopplerToken, dopplerProject, dopplerConfig, map[string]string{
		"VEIL_E2E_HTTPBIN_KEY": secretHTTPBin,
		"VEIL_E2E_ECHO_KEY":    secretEcho,
		"VEIL_E2E_BASIC_AUTH":  secretBasic,
	})

	// Test each backend
	for _, backend := range backends {
		backend := backend // capture for closure
		t.Run(backend, func(t *testing.T) {
			runBackendTests(t, ctx, veilBin, tmpDir, policyDir, echoAddr, dopplerToken,
				dopplerProject, dopplerConfig, secretHTTPBin, secretEcho, secretBasic, backend)
		})
	}
}

// detectAvailableBackends returns a list of available sandbox backends
func detectAvailableBackends() []string {
	var backends []string

	// Check for srt/anthropic backend
	if _, err := exec.LookPath("srt"); err == nil {
		backends = append(backends, "srt")
	}

	// Check for seatbelt backend (macOS only)
	if _, err := exec.LookPath("sandbox-exec"); err == nil {
		backends = append(backends, "seatbelt")
		backends = append(backends, "auto") // auto uses seatbelt on macOS
	}

	return backends
}

// runBackendTests runs all tests for a specific backend
func runBackendTests(t *testing.T, ctx context.Context, veilBin, tmpDir, policyDir, echoAddr, dopplerToken,
	dopplerProject, dopplerConfig, secretHTTPBin, secretEcho, secretBasic, backend string) {

	// Create backend-specific directories
	projectDir := filepath.Join(tmpDir, backend, "project")
	dataDir := filepath.Join(tmpDir, backend, "data")
	for _, dir := range []string{projectDir, dataDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create dir %s: %v", dir, err)
		}
	}

	// Create veil config for this backend
	configPath := filepath.Join(tmpDir, fmt.Sprintf("config-%s.yaml", backend))
	configContent := fmt.Sprintf(`routes:
  - host: "postman-echo.com"
    secret_id: VEIL_E2E_HTTPBIN_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"
  - host: "127.0.0.1"
    secret_id: VEIL_E2E_ECHO_KEY
    header_name: X-API-Key
    header_value_template: "{{secret}}"
  - host: "localhost"
    secret_id: VEIL_E2E_BASIC_AUTH
    header_name: Authorization
    header_value_template: "Basic {{secret}}"
doppler:
  project: %s
  config: %s
policy:
  enabled: true
  engine: opa
  policy_path: %s
  decision_path: veilwarden/authz/allow
sandbox:
  enabled: true
  backend: %s
  working_dir: %s
  allowed_write_paths: ["%s", "%s"]
  denied_read_paths: ["~/.ssh", "~/.aws", "~/.doppler", "~/.gnupg"]
`, dopplerProject, dopplerConfig, policyDir, backend, projectDir, projectDir, dataDir)

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Helper to run veil exec
	runVeil := func(args ...string) (string, error) {
		cmdArgs := append([]string{"exec", "--config", configPath, "--"}, args...)
		cmd := exec.CommandContext(ctx, veilBin, cmdArgs...)
		cmd.Env = append(os.Environ(), "DOPPLER_TOKEN="+dopplerToken)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// Create test scripts in project dir
	createTestScripts(t, projectDir, dataDir)

	// Run tests
	t.Run("SandboxEnvironment", func(t *testing.T) {
		testSandboxEnvironment(t, runVeil, projectDir)
	})

	t.Run("OPAPolicyEnforcement", func(t *testing.T) {
		testOPAPolicyEnforcement(t, runVeil, projectDir, secretHTTPBin)
	})

	t.Run("NetworkIsolation", func(t *testing.T) {
		testNetworkIsolation(t, runVeil, projectDir)
	})

	t.Run("RouteSecretIsolation", func(t *testing.T) {
		testRouteSecretIsolation(t, runVeil, projectDir, echoAddr, secretEcho, secretBasic)
	})

	t.Run("FilesystemEscapeAttempts", func(t *testing.T) {
		testFilesystemEscapes(t, runVeil, projectDir, dataDir)
	})

	t.Run("FilePersistence", func(t *testing.T) {
		// Clean up any existing test file
		os.Remove(filepath.Join(dataDir, "test.txt"))
		testFilePersistence(t, runVeil, projectDir, dataDir)
	})
}

func testSandboxEnvironment(t *testing.T, runVeil func(...string) (string, error), projectDir string) {
	out, err := runVeil("python3", filepath.Join(projectDir, "env_check.py"))
	if err != nil {
		t.Logf("output: %s", out)
	}

	result := extractJSON(out)
	var env struct {
		HTTPProxy    bool `json:"HTTP_PROXY"`
		HTTPSProxy   bool `json:"HTTPS_PROXY"`
		CACert       bool `json:"CA_CERT"`
		DopplerToken bool `json:"DOPPLER_TOKEN"`
	}
	if err := json.Unmarshal([]byte(result), &env); err != nil {
		t.Fatalf("failed to parse env check: %v\noutput: %s", err, out)
	}

	if !env.HTTPProxy {
		t.Error("HTTP_PROXY not set in sandbox")
	}
	if !env.HTTPSProxy {
		t.Error("HTTPS_PROXY not set in sandbox")
	}
	if !env.CACert {
		t.Error("CA cert not accessible in sandbox")
	}
	if env.DopplerToken {
		t.Error("DOPPLER_TOKEN leaked into sandbox")
	}
}

func testOPAPolicyEnforcement(t *testing.T, runVeil func(...string) (string, error), projectDir, expectedSecret string) {
	t.Run("AllowedGET", func(t *testing.T) {
		out, _ := runVeil("python3", filepath.Join(projectDir, "http_test.py"), "https://postman-echo.com/get", "GET")
		result := extractJSON(out)
		var resp struct {
			Headers struct {
				Authorization string `json:"authorization"`
			} `json:"headers"`
		}
		if err := json.Unmarshal([]byte(result), &resp); err != nil {
			t.Fatalf("failed to parse response: %v\noutput: %s", err, out)
		}
		expected := "Bearer " + expectedSecret
		if resp.Headers.Authorization != expected {
			t.Errorf("expected auth %q, got %q", expected, resp.Headers.Authorization)
		}
	})

	t.Run("DeniedGET", func(t *testing.T) {
		out, _ := runVeil("python3", filepath.Join(projectDir, "http_test.py"), "https://postman-echo.com/headers", "GET")
		if !strings.Contains(strings.ToLower(out), "policy") && !strings.Contains(out, "403") && !strings.Contains(out, "forbidden") {
			t.Errorf("expected policy denial, got: %s", out)
		}
	})

	t.Run("AllowedPOST", func(t *testing.T) {
		out, _ := runVeil("python3", filepath.Join(projectDir, "http_test.py"), "https://postman-echo.com/post", "POST")
		result := extractJSON(out)
		var resp struct {
			Headers struct {
				Authorization string `json:"authorization"`
			} `json:"headers"`
		}
		if err := json.Unmarshal([]byte(result), &resp); err != nil {
			t.Fatalf("failed to parse response: %v\noutput: %s", err, out)
		}
		expected := "Bearer " + expectedSecret
		if resp.Headers.Authorization != expected {
			t.Errorf("expected auth %q, got %q", expected, resp.Headers.Authorization)
		}
	})
}

func testNetworkIsolation(t *testing.T, runVeil func(...string) (string, error), projectDir string) {
	out, _ := runVeil("python3", filepath.Join(projectDir, "network_isolation.py"))
	result := extractJSON(out)

	var isolation struct {
		DirectTCP     struct{ Blocked bool } `json:"direct_tcp"`
		DirectHTTPS   struct{ Blocked bool } `json:"direct_https"`
		DNSResolution struct{ Blocked bool } `json:"dns_resolution"`
		RawSocket     struct{ Blocked bool } `json:"raw_socket"`
		AllBlocked    bool                   `json:"all_blocked"`
	}
	if err := json.Unmarshal([]byte(result), &isolation); err != nil {
		t.Fatalf("failed to parse isolation: %v\noutput: %s", err, out)
	}

	if !isolation.DirectTCP.Blocked {
		t.Error("direct_tcp not blocked")
	}
	if !isolation.DirectHTTPS.Blocked {
		t.Error("direct_https not blocked")
	}
	if !isolation.DNSResolution.Blocked {
		t.Error("dns_resolution not blocked")
	}
	if !isolation.RawSocket.Blocked {
		t.Error("raw_socket not blocked")
	}
	if !isolation.AllBlocked {
		t.Error("some network bypass attempts succeeded")
	}
}

func testRouteSecretIsolation(t *testing.T, runVeil func(...string) (string, error), projectDir, echoAddr, secretEcho, secretBasic string) {
	t.Run("LocalhostBasicAuth", func(t *testing.T) {
		// Use localhost for Basic auth route
		url := fmt.Sprintf("http://localhost:%s/api/test", strings.Split(echoAddr, ":")[1])
		out, _ := runVeil("python3", filepath.Join(projectDir, "http_test.py"), url, "GET")
		result := extractJSON(out)

		var resp struct {
			Headers struct {
				Authorization []string `json:"Authorization"`
			} `json:"headers"`
		}
		if err := json.Unmarshal([]byte(result), &resp); err != nil {
			t.Fatalf("failed to parse response: %v\noutput: %s", err, out)
		}

		expected := "Basic " + secretBasic
		if len(resp.Headers.Authorization) == 0 || resp.Headers.Authorization[0] != expected {
			t.Errorf("expected auth %q, got %v", expected, resp.Headers.Authorization)
		}
	})

	t.Run("127.0.0.1APIKey", func(t *testing.T) {
		// Use 127.0.0.1 for X-API-Key route
		url := fmt.Sprintf("http://%s/api/test", echoAddr)
		out, _ := runVeil("python3", filepath.Join(projectDir, "http_test.py"), url, "GET")
		result := extractJSON(out)

		var resp struct {
			Headers struct {
				XAPIKey []string `json:"X-Api-Key"`
			} `json:"headers"`
		}
		if err := json.Unmarshal([]byte(result), &resp); err != nil {
			t.Fatalf("failed to parse response: %v\noutput: %s", err, out)
		}

		if len(resp.Headers.XAPIKey) == 0 || resp.Headers.XAPIKey[0] != secretEcho {
			t.Errorf("expected X-API-Key %q, got %v", secretEcho, resp.Headers.XAPIKey)
		}
	})
}

func testFilesystemEscapes(t *testing.T, runVeil func(...string) (string, error), projectDir, dataDir string) {
	out, _ := runVeil("python3", filepath.Join(projectDir, "fs_escapes.py"), dataDir)
	result := extractJSON(out)

	var escapes struct {
		Symlink       struct{ Blocked bool } `json:"symlink"`
		PathTraversal struct{ Blocked bool } `json:"path_traversal"`
		WriteEscape   struct{ Blocked bool } `json:"write_escape"`
		Hardlink      struct{ Blocked bool } `json:"hardlink"`
		SensitiveRead struct{ Blocked bool } `json:"sensitive_read"`
		ProcAccess    struct{ Blocked bool } `json:"proc_access"`
		AllBlocked    bool                   `json:"all_blocked"`
		Summary       string                 `json:"summary"`
	}
	if err := json.Unmarshal([]byte(result), &escapes); err != nil {
		t.Fatalf("failed to parse escapes: %v\noutput: %s", err, out)
	}

	tests := []struct {
		name    string
		blocked bool
	}{
		{"symlink", escapes.Symlink.Blocked},
		{"path_traversal", escapes.PathTraversal.Blocked},
		{"write_escape", escapes.WriteEscape.Blocked},
		{"hardlink", escapes.Hardlink.Blocked},
		{"sensitive_read", escapes.SensitiveRead.Blocked},
		{"proc_access", escapes.ProcAccess.Blocked},
	}

	for _, tt := range tests {
		if !tt.blocked {
			t.Errorf("%s not blocked", tt.name)
		}
	}

	if escapes.Summary != "6/6" {
		t.Errorf("expected 6/6 escapes blocked, got %s", escapes.Summary)
	}
}

func testFilePersistence(t *testing.T, runVeil func(...string) (string, error), projectDir, dataDir string) {
	out, err := runVeil("python3", filepath.Join(projectDir, "persist_test.py"))
	if err != nil {
		t.Logf("persist test output: %s", out)
	}

	testFile := filepath.Join(dataDir, "test.txt")
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Error("file not persisted to host")
	}
}

// createTestScripts creates the Python test scripts in the project directory
func createTestScripts(t *testing.T, projectDir, dataDir string) {
	t.Helper()

	scripts := map[string]string{
		"env_check.py": `#!/usr/bin/env python3
import os, json
print(json.dumps({
    "HTTP_PROXY": bool(os.environ.get("HTTP_PROXY")),
    "HTTPS_PROXY": bool(os.environ.get("HTTPS_PROXY")),
    "CA_CERT": os.path.exists(os.environ.get("SSL_CERT_FILE", "")),
    "DOPPLER_TOKEN": "DOPPLER_TOKEN" in os.environ
}))
`,
		"http_test.py": `#!/usr/bin/env python3
import os, sys, json, urllib.request, ssl

url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9999/health"
method = sys.argv[2] if len(sys.argv) > 2 else "GET"

print(f"Request: {method} {url}", file=sys.stderr)
print(f"HTTP_PROXY: {os.environ.get('HTTP_PROXY', 'NOT_SET')}", file=sys.stderr)

try:
    ctx = ssl.create_default_context()
    ca = os.environ.get('SSL_CERT_FILE')
    if ca: ctx.load_verify_locations(ca)

    data = b'{}' if method == "POST" else None
    req = urllib.request.Request(url, method=method, data=data)
    req.add_header('User-Agent', 'curl/8.0')
    with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
        print(resp.read().decode('utf-8'))
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
`,
		"network_isolation.py": `#!/usr/bin/env python3
import json, os, socket, sys, urllib.request

results = {}
tests = [
    ("direct_tcp", lambda: socket.create_connection(('8.8.8.8', 80), timeout=3)),
    ("direct_https", lambda: urllib.request.build_opener(urllib.request.ProxyHandler({})).open('https://postman-echo.com/ip', timeout=3)),
    ("dns_resolution", lambda: socket.gethostbyname('canary.example.com')),
    ("raw_socket", lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)),
]
for name, fn in tests:
    try:
        fn()
        results[name] = {"blocked": False, "error": "SUCCEEDED - SECURITY RISK!"}
    except Exception as e:
        results[name] = {"blocked": True, "error": str(e)[:80]}

results["all_blocked"] = all(r["blocked"] for r in results.values())
print(json.dumps(results, indent=2))
`,
		"fs_escapes.py": `#!/usr/bin/env python3
import os, sys, json

results = {}
allowed_dir = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()

def test_escape(name, fn):
    try:
        fn()
        results[name] = {"blocked": False, "error": "SUCCEEDED - SECURITY RISK!"}
    except Exception as e:
        results[name] = {"blocked": True, "error": str(e)[:80]}

def try_symlink_read():
    link_path = os.path.join(allowed_dir, "link")
    target = os.path.expanduser("~/.ssh/id_rsa")
    os.symlink(target, link_path)
    return open(link_path).read(1)

def try_hardlink():
    link_path = os.path.join(allowed_dir, "hlink")
    target = os.path.expanduser("~/.ssh/known_hosts")
    os.link(target, link_path)

test_escape("symlink", try_symlink_read)
test_escape("path_traversal", lambda: open(os.path.join(allowed_dir, "../../../etc/passwd")).read(1))
test_escape("write_escape", lambda: open("/tmp/veil_escape_test", "w").write("test"))
test_escape("hardlink", try_hardlink)
test_escape("sensitive_read", lambda: open(os.path.expanduser("~/.ssh/id_rsa")).read(1))
test_escape("proc_access", lambda: open("/proc/self/cmdline").read(1))

results["all_blocked"] = all(r["blocked"] for r in results.values())
results["summary"] = f"{sum(1 for r in results.values() if isinstance(r,dict) and r.get('blocked'))}/{len([r for r in results.values() if isinstance(r,dict)])}"
print(json.dumps(results, indent=2))
`,
		"persist_test.py": fmt.Sprintf(`#!/usr/bin/env python3
import time
f = "%s/test.txt"
open(f, "w").write(f"sandbox-{time.time()}")
print(open(f).read())
`, dataDir),
	}

	for name, content := range scripts {
		path := filepath.Join(projectDir, name)
		if err := os.WriteFile(path, []byte(content), 0755); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
	}
}

// Helper functions

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}
	// Walk up to find go.mod
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root")
		}
		dir = parent
	}
}

func startEchoServer(t *testing.T) (string, *http.Server) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, _ := io.ReadAll(r.Body)

		resp := map[string]interface{}{
			"method":  r.Method,
			"path":    r.URL.Path,
			"headers": r.Header,
			"body":    string(body),
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

	return addr, server
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

func extractJSON(s string) string {
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return "{}"
}

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func setDopplerSecrets(t *testing.T, token, project, config string, secrets map[string]string) {
	t.Helper()

	secretsJSON, _ := json.Marshal(map[string]interface{}{"secrets": secrets})

	url := fmt.Sprintf("https://api.doppler.com/v3/configs/config/secrets?project=%s&config=%s", project, config)
	req, err := http.NewRequest("POST", url, bytes.NewReader(secretsJSON))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to set Doppler secrets: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("failed to set Doppler secrets: %d %s", resp.StatusCode, body)
	}
}

// TestExitCodePropagation verifies that exit codes from sandboxed commands
// are properly propagated to the parent process.
// NOTE: srt backend does NOT propagate exit codes (upstream limitation).
func TestExitCodePropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	dopplerToken := os.Getenv("DOPPLER_TOKEN")
	if dopplerToken == "" {
		t.Skip("DOPPLER_TOKEN not set")
	}

	// Only test with seatbelt backend which properly propagates exit codes
	// srt backend doesn't propagate exit codes (upstream limitation)
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("seatbelt (sandbox-exec) not available")
	}

	ctx := context.Background()
	tmpDir := t.TempDir()

	// Build veil binary
	veilBin := filepath.Join(tmpDir, "veil")
	repoRoot := findRepoRoot(t)
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", veilBin, "./cmd/veil")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build veil: %v\n%s", err, out)
	}

	// Use seatbelt backend which propagates exit codes correctly
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(`routes: []
doppler:
  project: veilwarden
  config: dev
sandbox:
  enabled: true
  backend: seatbelt
  working_dir: %s
`, tmpDir)
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	tests := []struct {
		name     string
		exitCode int
	}{
		{"exit_0", 0},
		{"exit_1", 1},
		{"exit_42", 42},
		{"exit_127", 127},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.CommandContext(ctx, veilBin, "exec", "--config", configPath, "--",
				"sh", "-c", fmt.Sprintf("exit %d", tt.exitCode))
			cmd.Env = append(os.Environ(), "DOPPLER_TOKEN="+dopplerToken)
			err := cmd.Run()

			var actualCode int
			if err == nil {
				actualCode = 0
			} else if exitErr, ok := err.(*exec.ExitError); ok {
				actualCode = exitErr.ExitCode()
			} else {
				t.Fatalf("unexpected error type: %v", err)
			}

			if actualCode != tt.exitCode {
				t.Errorf("expected exit code %d, got %d", tt.exitCode, actualCode)
			}
		})
	}
}

// TestSecretNotInOutput verifies that secrets injected into HTTP headers
// do not leak into veil's own logging output. Note: the secret appearing
// in HTTP responses from echo servers (like postman-echo) is expected
// behavior since those servers echo back headers.
func TestSecretNotInOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	dopplerToken := os.Getenv("DOPPLER_TOKEN")
	if dopplerToken == "" {
		t.Skip("DOPPLER_TOKEN not set")
	}

	backends := detectAvailableBackends()
	if len(backends) == 0 {
		t.Skip("no sandbox backends available")
	}

	ctx := context.Background()
	tmpDir := t.TempDir()
	projectDir := filepath.Join(tmpDir, "project")
	policyDir := filepath.Join(tmpDir, "policies")
	for _, dir := range []string{projectDir, policyDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create dir %s: %v", dir, err)
		}
	}

	// Build veil binary
	veilBin := filepath.Join(tmpDir, "veil")
	repoRoot := findRepoRoot(t)
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", veilBin, "./cmd/veil")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build veil: %v\n%s", err, out)
	}

	// Create permissive OPA policy - must allow CONNECT for proxy and GET for test
	policy := `package veilwarden.authz
import rego.v1
default allow := false
allow if { input.method == "CONNECT" }
allow if { input.method == "GET" }
`
	if err := os.WriteFile(filepath.Join(policyDir, "policy.rego"), []byte(policy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	// Create a unique secret that we can search for in output
	secretValue := fmt.Sprintf("SUPER_SECRET_%d_%x", time.Now().Unix(), time.Now().UnixNano()&0xFFFFFFFF)
	dopplerProject := getEnvOrDefault("DOPPLER_PROJECT", "veilwarden")
	dopplerConfig := getEnvOrDefault("DOPPLER_CONFIG", "dev")

	setDopplerSecrets(t, dopplerToken, dopplerProject, dopplerConfig, map[string]string{
		"VEIL_E2E_SECRET_LEAK_TEST": secretValue,
	})

	// Config with secret injection
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(`routes:
  - host: "postman-echo.com"
    secret_id: VEIL_E2E_SECRET_LEAK_TEST
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"
doppler:
  project: %s
  config: %s
policy:
  enabled: true
  engine: opa
  policy_path: %s
  decision_path: veilwarden/authz/allow
sandbox:
  enabled: true
  backend: %s
  working_dir: %s
`, dopplerProject, dopplerConfig, policyDir, backends[0], projectDir)
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Create a Python script that makes requests and captures only its own output
	// This allows us to separate veil's stderr from the command's output
	testScript := `#!/usr/bin/env python3
import os, sys, urllib.request, ssl, json

# Make a request - the response will contain the echoed header (expected)
url = "https://postman-echo.com/get"
ctx = ssl.create_default_context()
ca = os.environ.get('SSL_CERT_FILE')
if ca: ctx.load_verify_locations(ca)

req = urllib.request.Request(url)
try:
    with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
        # Just confirm request worked - don't print the response body
        # (which would contain the secret echoed back)
        print(json.dumps({"status": resp.status, "ok": resp.status == 200}))
except Exception as e:
    print(json.dumps({"error": str(e)}))
    sys.exit(1)
`
	scriptPath := filepath.Join(projectDir, "secret_test.py")
	if err := os.WriteFile(scriptPath, []byte(testScript), 0755); err != nil {
		t.Fatalf("failed to write test script: %v", err)
	}

	// Run with verbose to get veil's logging output
	cmd := exec.CommandContext(ctx, veilBin, "exec", "--config", configPath, "--verbose", "--",
		"python3", scriptPath)
	cmd.Env = append(os.Environ(), "DOPPLER_TOKEN="+dopplerToken)

	// Capture stderr separately (veil's logs go here)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, _ := cmd.Output()

	veilLogs := stderr.String()

	// Veil's logs should NOT contain the secret value
	// The log "injected secret host=... header=... secret_id=..." is OK (logs secret_id, not value)
	if strings.Contains(veilLogs, secretValue) {
		t.Errorf("SECRET LEAKED in veil's stderr logs! Found %q in:\n%s", secretValue, veilLogs)
	}

	// Verify the request actually succeeded
	// Skip if external service is unreachable/rate-limited (not a veil issue)
	if strings.Contains(string(stdout), "403") || strings.Contains(string(stdout), "429") {
		t.Skip("External service returned 403/429 - skipping (not a veil issue)")
	}
	if !strings.Contains(string(stdout), `"ok": true`) && !strings.Contains(string(stdout), `"status": 200`) {
		t.Logf("stdout: %s", stdout)
		t.Logf("stderr: %s", veilLogs)
		t.Skip("HTTP request failed - external service may be unavailable")
	}

	// Verify that the secret_id IS logged (expected behavior for debugging)
	if !strings.Contains(veilLogs, "VEIL_E2E_SECRET_LEAK_TEST") {
		t.Log("Note: secret_id not found in logs - verbose logging may have changed")
	}
}

// TestChildProcessSandboxed verifies that child processes spawned from within
// the sandbox are also subject to sandbox restrictions.
func TestChildProcessSandboxed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	dopplerToken := os.Getenv("DOPPLER_TOKEN")
	if dopplerToken == "" {
		t.Skip("DOPPLER_TOKEN not set")
	}

	backends := detectAvailableBackends()
	if len(backends) == 0 {
		t.Skip("no sandbox backends available")
	}

	ctx := context.Background()
	tmpDir := t.TempDir()
	projectDir := filepath.Join(tmpDir, "project")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatalf("failed to create project dir: %v", err)
	}

	// Build veil binary
	veilBin := filepath.Join(tmpDir, "veil")
	repoRoot := findRepoRoot(t)
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", veilBin, "./cmd/veil")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build veil: %v\n%s", err, out)
	}

	// Config with network and filesystem restrictions
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(`routes: []
doppler:
  project: veilwarden
  config: dev
sandbox:
  enabled: true
  backend: %s
  working_dir: %s
  allowed_write_paths: ["%s"]
  denied_read_paths: ["~/.ssh", "~/.aws"]
`, backends[0], projectDir, projectDir)
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Create a script that spawns child processes to test restrictions
	testScript := `#!/usr/bin/env python3
import subprocess, json, os, sys

results = {}

# Test 1: Child process trying direct network access
try:
    result = subprocess.run(
        ["python3", "-c", "import socket; socket.create_connection(('8.8.8.8', 80), timeout=3)"],
        capture_output=True, timeout=10
    )
    results["child_network"] = {"blocked": result.returncode != 0, "error": result.stderr.decode()[:80]}
except Exception as e:
    results["child_network"] = {"blocked": True, "error": str(e)[:80]}

# Test 2: Child process trying to read sensitive file
try:
    result = subprocess.run(
        ["python3", "-c", "print(open('" + os.path.expanduser("~/.ssh/id_rsa") + "').read(1))"],
        capture_output=True, timeout=10
    )
    results["child_fs_read"] = {"blocked": result.returncode != 0 or b"Error" in result.stderr, "error": result.stderr.decode()[:80]}
except Exception as e:
    results["child_fs_read"] = {"blocked": True, "error": str(e)[:80]}

# Test 3: Shell subprocess trying network access
try:
    result = subprocess.run(
        ["sh", "-c", "curl -m 3 http://8.8.8.8 2>&1"],
        capture_output=True, timeout=10
    )
    # Should fail with connection error
    results["shell_network"] = {"blocked": b"Could not" in result.stdout or result.returncode != 0, "output": result.stdout.decode()[:80]}
except Exception as e:
    results["shell_network"] = {"blocked": True, "error": str(e)[:80]}

# Test 4: Forked process inherits restrictions
try:
    result = subprocess.run(
        ["python3", "-c", """
import os
pid = os.fork()
if pid == 0:
    import socket
    try:
        socket.create_connection(('8.8.8.8', 80), timeout=3)
        os._exit(0)  # Should not reach here
    except:
        os._exit(1)  # Expected - blocked
else:
    _, status = os.waitpid(pid, 0)
    exit(0 if os.WEXITSTATUS(status) == 1 else 1)
"""],
        capture_output=True, timeout=10
    )
    results["forked_process"] = {"blocked": result.returncode == 0, "error": result.stderr.decode()[:80]}
except Exception as e:
    results["forked_process"] = {"blocked": True, "error": str(e)[:80]}

results["all_blocked"] = all(r.get("blocked", False) for r in results.values() if isinstance(r, dict))
print(json.dumps(results, indent=2))
`
	scriptPath := filepath.Join(projectDir, "child_test.py")
	if err := os.WriteFile(scriptPath, []byte(testScript), 0755); err != nil {
		t.Fatalf("failed to write test script: %v", err)
	}

	// Run test
	cmd := exec.CommandContext(ctx, veilBin, "exec", "--config", configPath, "--",
		"python3", scriptPath)
	cmd.Env = append(os.Environ(), "DOPPLER_TOKEN="+dopplerToken)
	output, _ := cmd.CombinedOutput()

	result := extractJSON(string(output))
	var childTests struct {
		ChildNetwork  struct{ Blocked bool } `json:"child_network"`
		ChildFSRead   struct{ Blocked bool } `json:"child_fs_read"`
		ShellNetwork  struct{ Blocked bool } `json:"shell_network"`
		ForkedProcess struct{ Blocked bool } `json:"forked_process"`
		AllBlocked    bool                   `json:"all_blocked"`
	}
	if err := json.Unmarshal([]byte(result), &childTests); err != nil {
		t.Logf("output: %s", output)
		t.Fatalf("failed to parse child test results: %v", err)
	}

	if !childTests.ChildNetwork.Blocked {
		t.Error("child_network: child process bypassed network restrictions")
	}
	if !childTests.ChildFSRead.Blocked {
		t.Error("child_fs_read: child process bypassed filesystem restrictions")
	}
	if !childTests.ShellNetwork.Blocked {
		t.Error("shell_network: shell subprocess bypassed network restrictions")
	}
	if !childTests.ForkedProcess.Blocked {
		t.Error("forked_process: forked process bypassed restrictions")
	}
}

// TestTempFileCleanup verifies that temporary files (CA certs, settings)
// are cleaned up even when commands fail.
func TestTempFileCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	dopplerToken := os.Getenv("DOPPLER_TOKEN")
	if dopplerToken == "" {
		t.Skip("DOPPLER_TOKEN not set")
	}

	backends := detectAvailableBackends()
	if len(backends) == 0 {
		t.Skip("no sandbox backends available")
	}

	ctx := context.Background()
	tmpDir := t.TempDir()

	// Build veil binary
	veilBin := filepath.Join(tmpDir, "veil")
	repoRoot := findRepoRoot(t)
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", veilBin, "./cmd/veil")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build veil: %v\n%s", err, out)
	}

	// Minimal config
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(`routes: []
doppler:
  project: veilwarden
  config: dev
sandbox:
  enabled: true
  backend: %s
  working_dir: %s
`, backends[0], tmpDir)
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	countVeilTempFiles := func() int {
		matches, _ := filepath.Glob("/tmp/veil-*")
		srtMatches, _ := filepath.Glob("/tmp/srt-*")
		return len(matches) + len(srtMatches)
	}

	t.Run("SuccessfulCommand", func(t *testing.T) {
		before := countVeilTempFiles()

		cmd := exec.CommandContext(ctx, veilBin, "exec", "--config", configPath, "--",
			"true")
		cmd.Env = append(os.Environ(), "DOPPLER_TOKEN="+dopplerToken)
		cmd.Run()

		// Give a moment for cleanup
		time.Sleep(100 * time.Millisecond)

		after := countVeilTempFiles()
		if after > before {
			t.Errorf("temp files leaked: before=%d, after=%d", before, after)
		}
	})

	t.Run("FailedCommand", func(t *testing.T) {
		before := countVeilTempFiles()

		cmd := exec.CommandContext(ctx, veilBin, "exec", "--config", configPath, "--",
			"false")
		cmd.Env = append(os.Environ(), "DOPPLER_TOKEN="+dopplerToken)
		cmd.Run()

		time.Sleep(100 * time.Millisecond)

		after := countVeilTempFiles()
		if after > before {
			t.Errorf("temp files leaked on failure: before=%d, after=%d", before, after)
		}
	})

	t.Run("CommandTimeout", func(t *testing.T) {
		before := countVeilTempFiles()

		timeoutCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		cmd := exec.CommandContext(timeoutCtx, veilBin, "exec", "--config", configPath, "--",
			"sleep", "10")
		cmd.Env = append(os.Environ(), "DOPPLER_TOKEN="+dopplerToken)
		cmd.Run()

		time.Sleep(200 * time.Millisecond)

		after := countVeilTempFiles()
		if after > before {
			t.Errorf("temp files leaked on timeout: before=%d, after=%d", before, after)
		}
	})
}

// TestConcurrentSandboxes verifies that multiple sandbox executions can run
// concurrently without port conflicts or resource interference.
func TestConcurrentSandboxes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	dopplerToken := os.Getenv("DOPPLER_TOKEN")
	if dopplerToken == "" {
		t.Skip("DOPPLER_TOKEN not set")
	}

	backends := detectAvailableBackends()
	if len(backends) == 0 {
		t.Skip("no sandbox backends available")
	}

	ctx := context.Background()
	tmpDir := t.TempDir()

	// Build veil binary
	veilBin := filepath.Join(tmpDir, "veil")
	repoRoot := findRepoRoot(t)
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", veilBin, "./cmd/veil")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build veil: %v\n%s", err, out)
	}

	// Create configs for concurrent executions
	const numConcurrent = 5
	var configs []string

	for i := 0; i < numConcurrent; i++ {
		projectDir := filepath.Join(tmpDir, fmt.Sprintf("project-%d", i))
		if err := os.MkdirAll(projectDir, 0755); err != nil {
			t.Fatalf("failed to create project dir: %v", err)
		}

		configPath := filepath.Join(tmpDir, fmt.Sprintf("config-%d.yaml", i))
		configContent := fmt.Sprintf(`routes: []
doppler:
  project: veilwarden
  config: dev
sandbox:
  enabled: true
  backend: %s
  working_dir: %s
  allowed_write_paths: ["%s"]
`, backends[0], projectDir, projectDir)
		if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
			t.Fatalf("failed to write config: %v", err)
		}
		configs = append(configs, configPath)

		// Create a test file to verify isolation
		testScript := fmt.Sprintf(`#!/bin/sh
echo "sandbox-%d: $$"
sleep 1
echo "sandbox-%d: done"
`, i, i)
		if err := os.WriteFile(filepath.Join(projectDir, "test.sh"), []byte(testScript), 0755); err != nil {
			t.Fatalf("failed to write test script: %v", err)
		}
	}

	// Run all sandboxes concurrently
	type result struct {
		index  int
		output string
		err    error
	}

	results := make(chan result, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		go func(idx int) {
			projectDir := filepath.Join(tmpDir, fmt.Sprintf("project-%d", idx))
			cmd := exec.CommandContext(ctx, veilBin, "exec", "--config", configs[idx], "--",
				"sh", filepath.Join(projectDir, "test.sh"))
			cmd.Env = append(os.Environ(), "DOPPLER_TOKEN="+dopplerToken)
			out, err := cmd.CombinedOutput()
			results <- result{index: idx, output: string(out), err: err}
		}(i)
	}

	// Collect results
	var failed []int
	for i := 0; i < numConcurrent; i++ {
		r := <-results
		if r.err != nil {
			t.Logf("sandbox-%d failed: %v\noutput: %s", r.index, r.err, r.output)
			failed = append(failed, r.index)
		} else {
			expected := fmt.Sprintf("sandbox-%d:", r.index)
			if !strings.Contains(r.output, expected) {
				t.Errorf("sandbox-%d: expected output containing %q, got: %s", r.index, expected, r.output)
			}
		}
	}

	if len(failed) > 0 {
		t.Errorf("%d/%d concurrent sandboxes failed: %v", len(failed), numConcurrent, failed)
	}
}
