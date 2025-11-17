package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type runConfig struct {
	listenAddr        string
	configPath        string
	sessionSecret     string
	dopplerToken      string
	dopplerBaseURL    string
	dopplerProject    string
	dopplerConfig     string
	cacheTTL          time.Duration
	dopplerTimeout    time.Duration
	otelEnabled       bool
	userID            string
	userEmail         string
	userOrg           string
	k8sEnabled        string // "auto", "true", "false"
	k8sAPIServer      string
	k8sValidateMethod string
}

func main() {
	// Initialize structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg := parseRunConfig()

	// Initialize OpenTelemetry
	ctx := context.Background()
	otelShutdown, err := initTelemetry(telemetryConfig{
		enabled: cfg.otelEnabled,
		logger:  logger,
	})
	if err != nil {
		logger.Error("Failed to initialize telemetry", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := otelShutdown(ctx); err != nil {
			logger.Error("Failed to shutdown telemetry", "error", err)
		}
	}()

	appCfg, err := loadAppConfig(cfg.configPath)
	if err != nil {
		logger.Error("Failed to load config",
			"config_path", cfg.configPath,
			"error", err,
			"hint", "Verify the file exists and contains valid YAML with a 'routes' section")
		os.Exit(1) //nolint:gocritic // exitAfterDefer is acceptable in main
	}

	store, err := buildSecretStore(&cfg, appCfg)
	if err != nil {
		logger.Error("Failed to configure secret store", "error", err)
		os.Exit(1)
	}

	// Initialize policy engine
	policyEngine := buildPolicyEngine(ctx, appCfg.policy)

	// Initialize Kubernetes authenticator
	k8sAuth := buildK8sAuthenticator(&cfg, appCfg, logger)

	server := newProxyServer(appCfg.routes, cfg.sessionSecret, store, logger, policyEngine, k8sAuth, cfg.userID, cfg.userEmail, cfg.userOrg)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/", server.handleHTTP)

	httpServer := &http.Server{
		Addr:         cfg.listenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("veilwarden starting", "listen_addr", cfg.listenAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down gracefully")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
}

func parseRunConfig() runConfig {
	var cfg runConfig
	flag.StringVar(&cfg.listenAddr, "listen", "127.0.0.1:8088", "address for the HTTP server")
	flag.StringVar(&cfg.configPath, "config", "veilwarden.yaml", "path to the route configuration")
	flag.StringVar(&cfg.sessionSecret, "session-secret", "", "session secret required from agents (overrides VEILWARDEN_SESSION_SECRET)")
	flag.StringVar(&cfg.dopplerToken, "doppler-token", "", "Doppler access token (overrides VEILWARDEN_DOPPLER_TOKEN or DOPPLER_TOKEN)")
	flag.StringVar(&cfg.dopplerBaseURL, "doppler-base-url", "https://api.doppler.com", "Doppler API base URL")
	flag.StringVar(&cfg.dopplerProject, "doppler-project", "", "Doppler project for secret lookups")
	flag.StringVar(&cfg.dopplerConfig, "doppler-config", "", "Doppler config for secret lookups")
	flag.DurationVar(&cfg.cacheTTL, "secret-cache-ttl", 5*time.Minute, "cache duration for resolved secrets")
	flag.DurationVar(&cfg.dopplerTimeout, "doppler-timeout", 5*time.Second, "timeout for Doppler HTTP requests")
	flag.BoolVar(&cfg.otelEnabled, "otel-enabled", false, "enable OpenTelemetry tracing and metrics")
	flag.StringVar(&cfg.userID, "user-id", "", "user ID for policy context (optional)")
	flag.StringVar(&cfg.userEmail, "user-email", "", "user email for policy context (optional)")
	flag.StringVar(&cfg.userOrg, "user-org", "", "user organization for policy context (optional)")
	flag.StringVar(&cfg.k8sEnabled, "k8s-enabled", "auto", "enable Kubernetes authentication (auto/true/false)")
	flag.StringVar(&cfg.k8sAPIServer, "k8s-api-server", "https://kubernetes.default.svc", "Kubernetes API server URL")
	flag.StringVar(&cfg.k8sValidateMethod, "k8s-validate-method", "tokenreview", "token validation method (tokenreview)")
	flag.Parse()

	if cfg.sessionSecret == "" {
		cfg.sessionSecret = os.Getenv("VEILWARDEN_SESSION_SECRET")
	}
	if cfg.sessionSecret == "" {
		fmt.Fprintf(os.Stderr, "Session secret is required but not provided.\n"+
			"Provide it using one of:\n"+
			"  1. --session-secret flag: veilwarden --session-secret='<random-secret>'\n"+
			"  2. VEILWARDEN_SESSION_SECRET environment variable\n"+
			"Generate a secure random secret with: openssl rand -base64 32\n")
		os.Exit(1)
	}

	cfg.dopplerToken = firstNonEmpty(
		cfg.dopplerToken,
		os.Getenv("VEILWARDEN_DOPPLER_TOKEN"),
		os.Getenv("DOPPLER_TOKEN"),
	)
	cfg.dopplerProject = firstNonEmpty(
		cfg.dopplerProject,
		os.Getenv("VEILWARDEN_DOPPLER_PROJECT"),
		os.Getenv("DOPPLER_PROJECT"),
	)
	cfg.dopplerConfig = firstNonEmpty(
		cfg.dopplerConfig,
		os.Getenv("VEILWARDEN_DOPPLER_CONFIG"),
		os.Getenv("DOPPLER_CONFIG"),
	)

	return cfg
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, fmt.Sprintf("method %s not allowed", r.Method), http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	//nolint:errcheck // Health check response write failure is non-recoverable
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func buildSecretStore(cfg *runConfig, appCfg *appConfig) (secretStore, error) {
	if cfg.dopplerToken != "" {
		if cfg.dopplerProject == "" || cfg.dopplerConfig == "" {
			return nil, fmt.Errorf("Doppler project and config are required when using a Doppler token.\n" +
				"Provide them using:\n" +
				"  --doppler-project and --doppler-config flags, OR\n" +
				"  DOPPLER_PROJECT and DOPPLER_CONFIG environment variables")
		}
		return newDopplerSecretStore(&dopplerOptions{
			token:    cfg.dopplerToken,
			baseURL:  cfg.dopplerBaseURL,
			project:  cfg.dopplerProject,
			config:   cfg.dopplerConfig,
			cacheTTL: cfg.cacheTTL,
			timeout:  cfg.dopplerTimeout,
		}), nil
	}
	if len(appCfg.secrets) == 0 {
		return nil, fmt.Errorf("No secrets configured.\n" +
			"Either:\n" +
			"  1. Provide a Doppler token (--doppler-token or DOPPLER_TOKEN env var), OR\n" +
			"  2. Add a 'secrets' section to your veilwarden.yaml config file")
	}
	if missing := missingConfigSecrets(appCfg); len(missing) > 0 {
		return nil, fmt.Errorf("Routes reference secrets that don't have values: %s\n"+
			"Add these secrets to the 'secrets' section in your config file", strings.Join(missing, ", "))
	}
	return &configSecretStore{secrets: appCfg.secrets}, nil
}

func buildPolicyEngine(ctx context.Context, cfg policyConfig) PolicyEngine {
	// If policy disabled, return allow-all config engine
	if !cfg.Enabled {
		return newConfigPolicyEngine(policyConfig{
			Enabled:      false,
			DefaultAllow: true,
		})
	}

	// Select engine based on config
	switch cfg.Engine {
	case "opa":
		engine, err := newOPAPolicyEngine(ctx, cfg)
		if err != nil {
			slog.Error("Failed to initialize OPA policy engine",
				"error", err,
				"hint", "Verify policy_path exists and contains valid .rego files")
			os.Exit(1)
		}
		slog.Info("OPA policy engine initialized",
			"policy_path", cfg.PolicyPath,
			"decision_path", cfg.DecisionPath)
		return engine
	case "config", "":
		return newConfigPolicyEngine(cfg)
	default:
		slog.Error("Unknown policy engine",
			"engine", cfg.Engine,
			"hint", "Valid engines: 'config', 'opa'")
		os.Exit(1)
		return nil
	}
}

func buildK8sAuthenticator(runCfg *runConfig, appCfg *appConfig, logger *slog.Logger) *k8sAuthenticator {
	// Determine final enabled value: CLI flag overrides config file
	k8sEnabledValue := appCfg.kubernetes.enabled
	if runCfg.k8sEnabled != "auto" {
		k8sEnabledValue = runCfg.k8sEnabled
	}

	// Determine if we should enable K8s authentication
	shouldEnableK8s := false
	switch k8sEnabledValue {
	case "true":
		shouldEnableK8s = true
		logger.Info("Kubernetes authentication explicitly enabled")
	case "false":
		shouldEnableK8s = false
		logger.Info("Kubernetes authentication explicitly disabled")
	case "auto":
		// Auto-detect: check if we're running in Kubernetes
		tokenPath := appCfg.kubernetes.tokenPath
		if _, err := os.Stat(tokenPath); err == nil {
			shouldEnableK8s = true
			logger.Info("Kubernetes authentication auto-detected",
				"token_path", tokenPath,
				"hint", "Service account token file found")
		} else {
			shouldEnableK8s = false
			logger.Info("Kubernetes authentication not detected",
				"token_path", tokenPath,
				"hint", "Service account token file not found, K8s auth disabled")
		}
	}

	// If disabled, return nil (no authenticator)
	if !shouldEnableK8s {
		return nil
	}

	// Create the authenticator
	k8sAuth, err := newK8sAuthenticator(true)
	if err != nil {
		logger.Error("Failed to initialize Kubernetes authenticator",
			"error", err,
			"hint", "Verify Kubernetes API server is accessible and RBAC permissions are configured")
		os.Exit(1)
	}

	logger.Info("Kubernetes authentication enabled",
		"api_server", runCfg.k8sAPIServer,
		"validate_method", runCfg.k8sValidateMethod)

	return k8sAuth
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func missingConfigSecrets(cfg *appConfig) []string {
	values := make(map[string]struct{}, len(cfg.secrets))
	for id := range cfg.secrets {
		values[id] = struct{}{}
	}
	seen := make(map[string]struct{})
	var missing []string
	for _, r := range cfg.routes {
		if _, ok := values[r.secretID]; !ok {
			if _, dup := seen[r.secretID]; !dup {
				missing = append(missing, r.secretID)
				seen[r.secretID] = struct{}{}
			}
		}
	}
	return missing
}
