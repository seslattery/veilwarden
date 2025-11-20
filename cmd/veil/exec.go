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

	"github.com/spf13/cobra"
	"veilwarden/cmd/veil/mitm"
	"veilwarden/internal/policy/opa"
	"veilwarden/internal/proxy"
)

var execCmd = &cobra.Command{
	Use:   "exec [flags] -- <command> [args...]",
	Short: "Execute command through VeilWarden MITM proxy",
	Long: `Run a command with HTTP_PROXY and CA environment variables set to route
traffic through VeilWarden's MITM proxy for transparent credential injection.

The proxy starts before the command and stops when the command exits.

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
	execCmd.Flags().BoolVar(&execVerbose, "verbose", false, "Show proxy logs for debugging")
	execCmd.Flags().IntVar(&execPort, "port", 0, "Proxy listen port (0 = random)")
}

func runExec(cmd *cobra.Command, args []string) error {
	// Check for unimplemented features
	if execSandbox {
		return fmt.Errorf(
			"sandbox mode is not yet implemented\n\n" +
			"The --sandbox flag is currently non-functional and provides no isolation.\n" +
			"Track implementation progress at: https://github.com/yourusername/veilwarden/issues/TBD\n\n" +
			"To run without sandboxing, remove the --sandbox flag.",
		)
	}

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
	defer ca.Cleanup()

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

	// For MVP: Use in-memory secret store (TODO: Doppler integration)
	secrets := map[string]string{
		"OPENAI_API_KEY":    os.Getenv("OPENAI_API_KEY"),
		"ANTHROPIC_API_KEY": os.Getenv("ANTHROPIC_API_KEY"),
		"GITHUB_TOKEN":      os.Getenv("GITHUB_TOKEN"),
	}
	secretStore := proxy.NewMemorySecretStore(secrets)

	// Build policy engine from config (defaults to allow-all if not configured)
	policyEngine, err := buildPolicyEngine(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize policy engine: %w", err)
	}

	// Find available port
	proxyPort := execPort
	if proxyPort == 0 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("failed to find available port: %w", err)
		}
		proxyPort = listener.Addr().(*net.TCPAddr).Port
		listener.Close()
	}

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
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

	// Start proxy in goroutine
	proxyListener, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", proxyAddr, err)
	}
	defer proxyListener.Close()

	proxyErrChan := make(chan error, 1)
	go func() {
		proxyErrChan <- proxyServer.Serve(proxyListener)
	}()

	// Give proxy time to start
	time.Sleep(100 * time.Millisecond)

	// Build environment variables with proxy URL and CA cert
	childEnv := buildProxyEnv(os.Environ(), proxyURL, ca.CertPath)

	// Execute command
	commandPath := args[0]
	commandArgs := args[1:]

	childCmd := exec.CommandContext(ctx, commandPath, commandArgs...)
	childCmd.Stdin = os.Stdin
	childCmd.Stdout = os.Stdout
	childCmd.Stderr = os.Stderr
	childCmd.Env = childEnv

	if err := childCmd.Run(); err != nil {
		// Check if proxy errored
		select {
		case proxyErr := <-proxyErrChan:
			return fmt.Errorf("proxy error: %w (command may have also failed: %v)", proxyErr, err)
		default:
			return fmt.Errorf("command failed: %w", err)
		}
	}

	return nil
}

func buildProxyEnv(parentEnv []string, proxyURL, caCertPath string) []string {
	env := make([]string, 0, len(parentEnv)+15)

	// Copy parent env, filtering out existing proxy vars
	for _, e := range parentEnv {
		key := strings.SplitN(e, "=", 2)[0]
		lower := strings.ToLower(key)

		// Strip DOPPLER_TOKEN (master credential that can access all secrets)
		if key == "DOPPLER_TOKEN" {
			continue
		}

		if strings.HasPrefix(lower, "http_proxy") ||
			strings.HasPrefix(lower, "https_proxy") ||
			strings.Contains(lower, "_ca_") {
			continue // Skip existing proxy env vars
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
		"REQUESTS_CA_BUNDLE="+caCertPath,   // Python requests
		"SSL_CERT_FILE="+caCertPath,        // Go, curl
		"NODE_EXTRA_CA_CERTS="+caCertPath,  // Node.js
		"CURL_CA_BUNDLE="+caCertPath,       // curl (alternate)
		"PIP_CERT="+caCertPath,             // pip
		"HTTPLIB2_CA_CERTS="+caCertPath,    // Python httplib2
		"AWS_CA_BUNDLE="+caCertPath,        // AWS CLI

		// VeilWarden-specific
		"VEILWARDEN_PROXY_URL="+proxyURL,
	)

	return env
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
