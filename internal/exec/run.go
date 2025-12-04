package exec

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	osexec "os/exec"
	"strings"
	"time"

	"veilwarden/internal/cert"
	"veilwarden/internal/config"
	"veilwarden/internal/env"
	"veilwarden/internal/policy/opa"
	"veilwarden/internal/proxy"
	"veilwarden/internal/secrets"
	"veilwarden/pkg/warden"
)

// Options configures the exec behavior.
type Options struct {
	Verbose bool
	Port    int
}

// Run executes a command through the VeilWarden proxy.
func Run(ctx context.Context, cfg *config.Config, args []string, sandboxBackend warden.Backend, opts Options) error {
	// Generate session ID
	sessionID, err := generateSessionID()
	if err != nil {
		return fmt.Errorf("failed to generate session ID: %w", err)
	}

	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "Session ID: %s\n", sessionID)
	}

	// Generate ephemeral CA
	ca, err := cert.GenerateEphemeralCA(sessionID)
	if err != nil {
		return fmt.Errorf("failed to generate CA: %w", err)
	}
	defer func() {
		if err := ca.Cleanup(); err != nil && opts.Verbose {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}
	}()

	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "CA cert: %s\n", ca.CertPath)
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
	secretStore, err := secrets.NewStore(cfg)
	if err != nil {
		return fmt.Errorf("failed to build secret store: %w", err)
	}

	// Build policy engine from config (defaults to allow-all if not configured)
	policyEngine, err := buildPolicyEngine(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize policy engine: %w", err)
	}

	// Find available port and keep listener open to prevent race
	proxyPort := opts.Port
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

	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "Proxy URL: %s\n", proxyURL)
	}

	// Create proxy server
	var logger *slog.Logger
	if opts.Verbose {
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
	childEnv := env.BuildProxyEnv(os.Environ(), proxyURL, ca.CertPath, envPassthrough)

	// Execute command (sandboxed or direct)
	var cmdErr error
	if sandboxBackend != nil {
		cmdErr = runSandboxed(ctx, sandboxBackend, cfg, args, childEnv, proxyAddr, ca.CertPath)
	} else {
		// Direct execution (existing behavior)
		commandPath := args[0]
		commandArgs := args[1:]

		childCmd := osexec.CommandContext(ctx, commandPath, commandArgs...)
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
			if exitErr, ok := cmdErr.(*osexec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			return fmt.Errorf("command failed: %w", cmdErr)
		}
	}

	return nil
}

// runSandboxed executes the command in a sandbox with network isolation
func runSandboxed(ctx context.Context, backend warden.Backend, cfg *config.Config, args, childEnv []string, proxyAddr, caCertPath string) error {
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
		Env:        childEnv,
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

func buildPolicyEngine(cfg *config.Config) (proxy.PolicyEngine, error) {
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
