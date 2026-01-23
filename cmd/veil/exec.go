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
	execLogFile    string
	execTier       string
	execPermissive bool
	execParanoid   bool
)

func init() {
	rootCmd.AddCommand(execCmd)

	execCmd.Flags().StringVar(&execConfigPath, "config", "", "Configuration file path (default: auto-discover .veilwarden/config.yaml)")
	execCmd.Flags().BoolVar(&execSandbox, "sandbox", false, "Enable sandbox-runtime filesystem isolation")
	execCmd.Flags().Bool("no-sandbox", false, "Disable sandbox even if enabled in config")
	execCmd.Flags().BoolVar(&execVerbose, "verbose", false, "Show proxy logs for debugging")
	execCmd.Flags().IntVar(&execPort, "port", 0, "Proxy listen port (0 = random)")
	execCmd.Flags().StringVar(&execLogFile, "log-file", "", "Write proxy logs to file (default: .veilwarden/proxy.log when verbose)")
	execCmd.Flags().StringVar(&execTier, "tier", "", "Sandbox security tier: standard (default), permissive, paranoid")
	execCmd.Flags().BoolVar(&execPermissive, "permissive", false, "Shorthand for --tier=permissive")
	execCmd.Flags().BoolVar(&execParanoid, "paranoid", false, "Shorthand for --tier=paranoid (deny-by-default file reads)")
}

func runExec(cmd *cobra.Command, args []string) error {
	// Use signal.NotifyContext for clean signal handling without goroutine leaks
	// This automatically stops signal handling when the context is cancelled
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Discover or load configuration
	configPath := execConfigPath
	if configPath == "" {
		// Auto-discover config
		configPath = config.DiscoverConfig()
		if configPath != "" && execVerbose {
			fmt.Fprintf(os.Stderr, "Discovered config: %s\n", configPath)
		}
	}

	var cfg *config.Config
	if configPath != "" {
		var err error
		cfg, err = config.Load(configPath)
		if err != nil {
			if execVerbose {
				fmt.Fprintf(os.Stderr, "Warning: failed to load config: %v\n", err)
				fmt.Fprintf(os.Stderr, "Using defaults...\n")
			}
			cfg = config.Default()
		}
	} else {
		if execVerbose {
			fmt.Fprintf(os.Stderr, "No config found, using defaults\n")
		}
		cfg = config.Default()
	}

	// Apply defaults for any unset values
	cfg.ApplyDefaults()

	// Apply tier override from CLI flags
	if err := applyTierOverride(cfg, cmd); err != nil {
		return err
	}

	if execVerbose {
		fmt.Fprintf(os.Stderr, "Config loaded: %d routes\n", len(cfg.Routes))
	}

	// Determine if sandbox should be used
	useSandbox := shouldUseSandbox(cfg, cmd)

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
		backend, err := warden.NewBackend(cfg.Sandbox.Backend)
		if err != nil {
			return fmt.Errorf("failed to create sandbox: %w", err)
		}
		sandboxBackend = backend
	}

	// Determine log file path
	logFile := execLogFile
	if logFile == "" && execVerbose && cfg.ConfigDir() != "" {
		// Default to .veilwarden/proxy.log when verbose is enabled
		logFile = cfg.ConfigDir() + "/proxy.log"
	}

	// Run the command through the proxy
	return exec.Run(ctx, cfg, args, sandboxBackend, exec.Options{
		Verbose: execVerbose,
		Port:    execPort,
		LogFile: logFile,
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

// applyTierOverride applies tier from CLI flags to config
func applyTierOverride(cfg *config.Config, cmd *cobra.Command) error {
	// --permissive and --paranoid are shorthands for --tier=X
	tierStr := execTier
	if execParanoid {
		tierStr = "paranoid"
	} else if execPermissive {
		tierStr = "permissive"
	}

	// Only apply if a tier was specified
	if tierStr == "" {
		return nil
	}

	// Validate the tier
	tier, err := warden.ParseTier(tierStr)
	if err != nil {
		return fmt.Errorf("invalid --tier value: %w", err)
	}

	// Ensure sandbox config exists
	if cfg.Sandbox == nil {
		cfg.Sandbox = &config.SandboxEntry{
			Enabled: true,
			Backend: "auto",
		}
	}

	// Apply the tier
	cfg.Sandbox.Tier = tier.String()

	// When downgrading to standard tier, clear permissive-only settings
	// that would otherwise pass through without validation
	if !tier.IsPermissive() {
		if len(cfg.Sandbox.AllowedUnixSockets) > 0 {
			fmt.Fprintf(os.Stderr, "Warning: clearing allowed_unix_sockets (requires permissive tier)\n")
			cfg.Sandbox.AllowedUnixSockets = nil
		}
		if cfg.Sandbox.AllowDangerousFiles {
			fmt.Fprintf(os.Stderr, "Warning: clearing allow_dangerous_files (requires permissive tier)\n")
			cfg.Sandbox.AllowDangerousFiles = false
		}
	}

	return nil
}
