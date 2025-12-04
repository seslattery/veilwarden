package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"veilwarden/cmd/veil/mitm"
	"veilwarden/internal/policy/opa"
	"veilwarden/internal/proxy"
	"veilwarden/pkg/warden"

	"github.com/spf13/cobra"
)

// shouldUseSandbox determines if sandbox should be used based on config and flags
func shouldUseSandbox(cfg *veilConfig, cmd *cobra.Command) bool {
	// --no-sandbox flag takes precedence
	if noSandbox, err := cmd.Flags().GetBool("no-sandbox"); err == nil && noSandbox {
		return false
	}

	// --sandbox flag overrides config
	if cmd.Flags().Changed("sandbox") {
		sandboxFlag, err := cmd.Flags().GetBool("sandbox")
		if err == nil {
			return sandboxFlag
		}
	}

	// Default to config
	return cfg.Sandbox != nil && cfg.Sandbox.Enabled
}

var execCmd = &cobra.Command{
	Use:   "exec [flags] -- <command> [args...]",
	Short: "Execute command through VeilWarden MITM proxy",
	Long: `Run a command with HTTP_PROXY and CA environment variables set to route
traffic through VeilWarden's MITM proxy for transparent credential injection.

The proxy starts before the command and stops when the command exits.

When sandbox is enabled, the command runs in an isolated environment with:
- Network access restricted to ONLY the proxy (prevents bypass)
- Filesystem access controlled via allowed_write_paths and denied_read_paths
- Sensitive credentials (DOPPLER_TOKEN) stripped from environment

Example:
  veil exec -- curl https://api.github.com/user
  veil exec -- python my_agent.py
  veil exec --sandbox -- python untrusted_agent.py`,
	Args: cobra.MinimumNArgs(1),
	RunE: runExec,
}

var (
	execConfigPath string
	execSandbox    bool
	execVerbose    bool
	execPort       int
)

func init() {
	rootCmd.AddCommand(execCmd)

	execCmd.Flags().StringVar(&execConfigPath, "config", "~/.veilwarden/config.yaml", "Configuration file path")
	execCmd.Flags().BoolVar(&execSandbox, "sandbox", false, "Enable sandbox-runtime filesystem isolation")
	execCmd.Flags().Bool("no-sandbox", false, "Disable sandbox even if enabled in config")
	execCmd.Flags().BoolVar(&execVerbose, "verbose", false, "Show proxy logs for debugging")
	execCmd.Flags().IntVar(&execPort, "port", 0, "Proxy listen port (0 = random)")
}

// waitForProxy waits for the proxy to be ready to accept connections.
func waitForProxy(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("proxy not ready after %v", timeout)
}

func runExec(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// Generate session ID
	sessionID, err := generateSessionID()
	if err != nil {
		return fmt.Errorf("failed to generate session ID: %w", err)
	}

	if execVerbose {
		fmt.Fprintf(os.Stderr, "Session ID: %s\n", sessionID)
	}

	// Generate ephemeral CA
	ca, err := mitm.GenerateEphemeralCA(sessionID)
	if err != nil {
		return fmt.Errorf("failed to generate CA: %w", err)
	}
	defer func() {
		if err := ca.Cleanup(); err != nil && execVerbose {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}
	}()

	if execVerbose {
		fmt.Fprintf(os.Stderr, "CA cert: %s\n", ca.CertPath)
	}

	// Load configuration
	cfg, err := loadVeilConfig(execConfigPath)
	if err != nil {
		if execVerbose {
			fmt.Fprintf(os.Stderr, "Warning: failed to load config: %v\n", err)
			fmt.Fprintf(os.Stderr, "Continuing without proxy...\n")
		}
		// Continue without proxy if config fails
		cfg = &veilConfig{}
	}

	if execVerbose {
		fmt.Fprintf(os.Stderr, "Config loaded: %d routes\n", len(cfg.Routes))
	}

	// Determine if sandbox should be used
	useSandbox := shouldUseSandbox(cfg, cmd)

	// Initialize sandbox config if needed
	if useSandbox && cfg.Sandbox == nil {
		cfg.Sandbox = &veilSandboxEntry{
			Enabled: true,
			Backend: "auto",
		}
	}

	if execVerbose {
		if useSandbox {
			fmt.Fprintf(os.Stderr, "Sandbox: enabled (backend: %s)\n", cfg.Sandbox.Backend)
		} else {
			fmt.Fprintf(os.Stderr, "Sandbox: disabled\n")
		}
	}

	// Create sandbox backend if enabled
	var sandboxBackend warden.Backend
	if useSandbox {
		backendType := cfg.Sandbox.Backend
		if backendType == "" {
			backendType = "auto"
		}
		backend, err := warden.NewBackend(backendType)
		if err != nil {
			return fmt.Errorf("failed to create sandbox: %w", err)
		}
		sandboxBackend = backend
	}

	// Convert routes to proxy.Route format
	routes := make(map[string]proxy.Route)
	for _, r := range cfg.Routes {
		routes[r.Host] = proxy.Route{
			UpstreamHost:        r.Host,
			SecretID:            r.SecretID,
			HeaderName:          r.HeaderName,
			HeaderValueTemplate: r.HeaderValueTemplate,
		}
	}

	// Build secret store (Doppler or in-memory)
	secretStore, err := buildSecretStore(cfg)
	if err != nil {
		return fmt.Errorf("failed to build secret store: %w", err)
	}

	// Build policy engine from config (defaults to allow-all if not configured)
	policyEngine, err := buildPolicyEngine(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize policy engine: %w", err)
	}

	// Find available port and keep listener open to prevent race
	proxyPort := execPort
	var proxyListener net.Listener

	if proxyPort == 0 {
		// Bind to random port and keep listener open
		var err error
		proxyListener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("failed to find available port: %w", err)
		}
		proxyPort = proxyListener.Addr().(*net.TCPAddr).Port
	} else {
		// Bind to specified port
		var err error
		proxyListener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
		if err != nil {
			return fmt.Errorf("failed to listen on port %d: %w", proxyPort, err)
		}
	}
	defer proxyListener.Close()

	proxyAddr := fmt.Sprintf("localhost:%d", proxyPort)
	proxyURL := fmt.Sprintf("http://%s", proxyAddr)

	if execVerbose {
		fmt.Fprintf(os.Stderr, "Proxy URL: %s\n", proxyURL)
	}

	// Create proxy server
	var logger *slog.Logger
	if execVerbose {
		logger = slog.Default()
	} else {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	proxyCfg := &proxy.MartianConfig{
		SessionID:    sessionID,
		CACert:       ca.CACert,
		CAKey:        ca.CAKey,
		Routes:       routes,
		SecretStore:  secretStore,
		PolicyEngine: policyEngine,
		Logger:       logger,
	}

	proxyServer, err := proxy.NewMartianProxy(proxyCfg)
	if err != nil {
		return fmt.Errorf("failed to create proxy: %w", err)
	}

	proxyErrChan := make(chan error, 1)
	go func() {
		proxyErrChan <- proxyServer.Serve(proxyListener)
	}()

	// Wait for proxy to be ready (with timeout)
	if err := waitForProxy(proxyAddr, 5*time.Second); err != nil {
		return fmt.Errorf("proxy startup failed: %w", err)
	}

	// Build environment variables with proxy URL and CA cert
	// Get passthrough list from sandbox config (if any)
	var envPassthrough []string
	if cfg.Sandbox != nil {
		envPassthrough = cfg.Sandbox.EnvPassthrough
	}
	childEnv := buildProxyEnv(os.Environ(), proxyURL, ca.CertPath, envPassthrough)

	// Execute command (sandboxed or direct)
	var cmdErr error
	if sandboxBackend != nil {
		cmdErr = runSandboxed(ctx, sandboxBackend, cfg, args, childEnv, proxyAddr, ca.CertPath)
	} else {
		// Direct execution (existing behavior)
		commandPath := args[0]
		commandArgs := args[1:]

		childCmd := exec.CommandContext(ctx, commandPath, commandArgs...)
		childCmd.Stdin = os.Stdin
		childCmd.Stdout = os.Stdout
		childCmd.Stderr = os.Stderr
		childCmd.Env = childEnv

		cmdErr = childCmd.Run()
	}

	if cmdErr != nil {
		// Check if proxy errored
		select {
		case proxyErr := <-proxyErrChan:
			return fmt.Errorf("proxy error: %w (command also failed: %v)", proxyErr, cmdErr)
		default:
			// Extract exit code from ExitError and propagate it
			if exitErr, ok := cmdErr.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			return fmt.Errorf("command failed: %w", cmdErr)
		}
	}

	return nil
}

// looksLikeSecret returns true if the env var name matches common secret patterns.
// This is a heuristic to strip credentials that agents shouldn't see.
func looksLikeSecret(key string) bool {
	upper := strings.ToUpper(key)

	// Common secret suffixes/patterns
	secretPatterns := []string{
		"_KEY",
		"_TOKEN",
		"_SECRET",
		"_PASSWORD",
		"_CREDENTIAL",
		"_CREDENTIALS",
		"_API_KEY",
		"_APIKEY",
		"_AUTH",
		"_PRIVATE",
	}

	for _, pattern := range secretPatterns {
		if strings.Contains(upper, pattern) {
			return true
		}
	}

	// Specific known sensitive vars
	sensitiveVars := map[string]bool{
		"DOPPLER_TOKEN":          true,
		"AWS_ACCESS_KEY_ID":      true,
		"AWS_SECRET_ACCESS_KEY":  true,
		"AWS_SESSION_TOKEN":      true,
		"GITHUB_TOKEN":           true,
		"GH_TOKEN":               true,
		"GITLAB_TOKEN":           true,
		"NPM_TOKEN":              true,
		"PYPI_TOKEN":             true,
		"DOCKER_PASSWORD":        true,
		"DOCKER_AUTH_CONFIG":     true,
		"KUBECONFIG":             true,
		"GOOGLE_APPLICATION_CREDENTIALS": true,
	}

	return sensitiveVars[upper]
}

func buildProxyEnv(parentEnv []string, proxyURL, caCertPath string, envPassthrough []string) []string {
	env := make([]string, 0, len(parentEnv)+15)

	// Build passthrough set for O(1) lookup
	passthroughSet := make(map[string]bool)
	for _, key := range envPassthrough {
		passthroughSet[strings.ToUpper(key)] = true
	}

	// Copy parent env, filtering out secrets and proxy vars
	for _, e := range parentEnv {
		key := strings.SplitN(e, "=", 2)[0]
		upper := strings.ToUpper(key)
		lower := strings.ToLower(key)

		// Always strip proxy-related vars (we set our own)
		if strings.HasPrefix(lower, "http_proxy") ||
			strings.HasPrefix(lower, "https_proxy") ||
			strings.Contains(lower, "_ca_") {
			continue
		}

		// Check if explicitly allowed via passthrough
		if passthroughSet[upper] {
			env = append(env, e)
			continue
		}

		// Strip vars that look like secrets
		if looksLikeSecret(key) {
			continue
		}

		env = append(env, e)
	}

	// Add proxy configuration
	env = append(env,
		// Standard proxy env vars (both cases for compatibility)
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,

		// CA certificate paths for various tools
		"REQUESTS_CA_BUNDLE="+caCertPath,  // Python requests
		"SSL_CERT_FILE="+caCertPath,       // Go, curl
		"NODE_EXTRA_CA_CERTS="+caCertPath, // Node.js
		"CURL_CA_BUNDLE="+caCertPath,      // curl (alternate)
		"PIP_CERT="+caCertPath,            // pip
		"HTTPLIB2_CA_CERTS="+caCertPath,   // Python httplib2
		"AWS_CA_BUNDLE="+caCertPath,       // AWS CLI

		// VeilWarden-specific
		"VEILWARDEN_PROXY_URL="+proxyURL,
	)

	return env
}

// runSandboxed executes the command in a sandbox with network isolation
func runSandboxed(ctx context.Context, backend warden.Backend, cfg *veilConfig, args, env []string, proxyAddr, caCertPath string) error {
	// Ensure CA cert path is readable by sandbox
	allowedReadPaths := cfg.Sandbox.AllowedReadPaths
	if caCertPath != "" {
		allowedReadPaths = append(allowedReadPaths, caCertPath)
	}

	// Extract hosts from routes for SRT backend allowedDomains
	allowedHosts := make([]string, 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		allowedHosts = append(allowedHosts, r.Host)
	}

	// Determine working directory - use config value or current directory
	workingDir := cfg.Sandbox.WorkingDir
	if workingDir == "" {
		var err error
		workingDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
	} else {
		workingDir = warden.ExpandPath(workingDir)
	}

	// Default allowed write paths to working directory if not specified
	allowedWritePaths := cfg.Sandbox.AllowedWritePaths
	if len(allowedWritePaths) == 0 {
		allowedWritePaths = []string{workingDir}
	}

	// Build sandbox config
	sandboxCfg := &warden.Config{
		Command:    args,
		Env:        env,
		WorkingDir: workingDir,
		ProxyAddr:  proxyAddr, // Critical: sandbox will ONLY allow connections to proxy

		// Filesystem access control
		AllowedWritePaths: allowedWritePaths,
		DeniedReadPaths:   cfg.Sandbox.DeniedReadPaths,
		AllowedReadPaths:  allowedReadPaths,

		// Network: hosts that can be accessed via proxy (for SRT backend)
		AllowedHosts: allowedHosts,
	}

	// Add default denied read paths if none specified
	if len(sandboxCfg.DeniedReadPaths) == 0 {
		sandboxCfg.DeniedReadPaths = warden.DefaultDeniedReadPaths()
	}

	// Start sandboxed process
	proc, err := backend.Start(ctx, sandboxCfg)
	if err != nil {
		return fmt.Errorf("sandbox start failed: %w", err)
	}

	// Pipe stdout/stderr to parent with error logging
	go func() {
		if _, err := io.Copy(os.Stdout, proc.Stdout); err != nil {
			// Only log if not a normal EOF/close
			if err != io.EOF && !strings.Contains(err.Error(), "closed") {
				fmt.Fprintf(os.Stderr, "veil: stdout pipe error: %v\n", err)
			}
		}
	}()
	go func() {
		if _, err := io.Copy(os.Stderr, proc.Stderr); err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "closed") {
				fmt.Fprintf(os.Stderr, "veil: stderr pipe error: %v\n", err)
			}
		}
	}()

	// Wait for completion
	return proc.Wait()
}

func buildPolicyEngine(cfg *veilConfig) (proxy.PolicyEngine, error) {
	// If no policy configured, default to allow-all (backward compatibility)
	if cfg.Policy == nil || cfg.Policy.Engine == "" || cfg.Policy.Engine == "disabled" {
		return proxy.NewAllowAllPolicyEngine(), nil
	}

	// If OPA policy
	if cfg.Policy.Engine == "opa" {
		if cfg.Policy.PolicyPath == "" {
			return nil, fmt.Errorf("policy.policy_path required when policy.engine is 'opa'")
		}

		decisionPath := cfg.Policy.DecisionPath
		if decisionPath == "" {
			decisionPath = "veilwarden/authz/allow"
		}

		return opa.New(context.Background(), cfg.Policy.PolicyPath, decisionPath)
	}

	return nil, fmt.Errorf("unknown policy engine type: %s (valid options: disabled, opa)", cfg.Policy.Engine)
}

func generateSessionID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
