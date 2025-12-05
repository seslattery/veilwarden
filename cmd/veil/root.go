package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// knownSubcommands lists all veil subcommands to distinguish from external commands
var knownSubcommands = map[string]bool{
	"exec":       true,
	"init":       true,
	"help":       true,
	"completion": true,
}

var rootCmd = &cobra.Command{
	Use:   "veil [flags] <command> [args...]",
	Short: "VeilWarden laptop MITM proxy for AI agents",
	Long: `veil is a CLI wrapper for VeilWarden that provides transparent
API credential injection for AI agents via MITM proxy.

AI agents run through veil have zero knowledge of API credentials,
which are fetched from Doppler and injected transparently.

Example:
  veil curl https://api.github.com/user
  veil python my_agent.py
  veil --sandbox python untrusted_agent.py`,
	Version: "2.0.0",
	// When args are provided, run exec behavior
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		return runExec(cmd, args)
	},
	// Disable Cobra's built-in "unknown command" error for non-subcommand args
	SilenceErrors: true,
	SilenceUsage:  true,
}

func Execute() {
	// Preprocess args: if first non-flag arg isn't a known subcommand,
	// treat everything after flags as the command to exec
	args := os.Args[1:]
	if shouldRewriteArgs(args) {
		// Find where flags end and command begins, then add "--" separator
		args = insertArgSeparator(args)
		rootCmd.SetArgs(args)
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// shouldRewriteArgs checks if we need to rewrite args for implicit exec
func shouldRewriteArgs(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			// Explicit separator, no rewrite needed
			return false
		}
		if strings.HasPrefix(arg, "-") {
			// Skip flags
			continue
		}
		// First non-flag argument
		return !knownSubcommands[arg]
	}
	return false
}

// insertArgSeparator adds "--" before the first non-flag argument
func insertArgSeparator(args []string) []string {
	var result []string
	separatorAdded := false

	for i, arg := range args {
		if !separatorAdded && !strings.HasPrefix(arg, "-") {
			// Insert separator before first non-flag arg
			result = append(result, "--")
			result = append(result, args[i:]...)
			separatorAdded = true
			break
		}
		result = append(result, arg)
	}

	return result
}

func init() {
	// Add exec flags to root command so `veil <cmd>` works like `veil exec -- <cmd>`
	rootCmd.Flags().StringVar(&execConfigPath, "config", "", "Configuration file path (default: auto-discover .veilwarden/config.yaml)")
	rootCmd.Flags().BoolVar(&execSandbox, "sandbox", false, "Enable sandbox-runtime filesystem isolation")
	rootCmd.Flags().Bool("no-sandbox", false, "Disable sandbox even if enabled in config")
	rootCmd.Flags().BoolVar(&execVerbose, "verbose", false, "Show proxy logs for debugging")
	rootCmd.Flags().IntVar(&execPort, "port", 0, "Proxy listen port (0 = random)")
}
