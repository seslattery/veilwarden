package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/seslattery/veilwarden/internal/config"
	"github.com/seslattery/veilwarden/internal/exec"
	"github.com/seslattery/veilwarden/pkg/warden"

	"github.com/spf13/cobra"
)

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

	// Load configuration
	cfg, err := config.Load(execConfigPath)
	if err != nil {
		if execVerbose {
			fmt.Fprintf(os.Stderr, "Warning: failed to load config: %v\n", err)
			fmt.Fprintf(os.Stderr, "Continuing without proxy...\n")
		}
		// Continue without proxy if config fails
		cfg = &config.Config{}
	}

	if execVerbose {
		fmt.Fprintf(os.Stderr, "Config loaded: %d routes\n", len(cfg.Routes))
	}

	// Determine if sandbox should be used
	useSandbox := shouldUseSandbox(cfg, cmd)

	// Initialize sandbox config if needed
	if useSandbox && cfg.Sandbox == nil {
		cfg.Sandbox = &config.SandboxEntry{
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

	// Run the command through the proxy
	return exec.Run(ctx, cfg, args, sandboxBackend, exec.Options{
		Verbose: execVerbose,
		Port:    execPort,
	})
}

// shouldUseSandbox determines if sandbox should be used based on config and flags
func shouldUseSandbox(cfg *config.Config, cmd *cobra.Command) bool {
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
