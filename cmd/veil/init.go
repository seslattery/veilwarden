package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/seslattery/veilwarden/pkg/warden"
)

// Embedded example files
var exampleConfig = `# VeilWarden configuration
#
# This config is auto-discovered when running veil from this directory or any subdirectory.
# All relative paths are resolved relative to this config file's directory.

# Routes define how secrets are injected into HTTP requests
# Secrets are loaded from environment variables (or Doppler if configured)
# Uncomment and customize routes as needed:
#
#routes:
#  - host: api.anthropic.com
#    secret_id: ANTHROPIC_API_KEY
#    header_name: x-api-key
#    header_value_template: "{{secret}}"
#
#  - host: api.openai.com
#    secret_id: OPENAI_API_KEY
#    header_name: Authorization
#    header_value_template: "Bearer {{secret}}"

# Optional: OPA policy for request authorization
# policy:
#   engine: opa
#   policy_path: ./policies          # Relative to this config file
#   decision_path: veilwarden/authz/allow

# Optional: Fetch secrets from Doppler instead of environment variables
# doppler:
#   project: my-project
#   config: dev

# Sandbox settings
sandbox:
  enabled: true
  backend: auto
  enable_pty: true                   # Required for interactive CLIs
  allowed_write_paths:
    - .                              # Project directory (relative to config)
    - /tmp
    - ~/.claude.json                 # Claude Code state
    - ~/.claude                      # Claude Code data
  denied_read_paths:
    - ~/.ssh
    - ~/.aws
    - ~/.config/gcloud
    - ~/.azure
    - ~/.kube
    - ~/.docker
    - ~/.doppler
    - ~/.gnupg
    - ~/.vault-token
    - ~/.netrc
    - ~/.git-credentials
`

var examplePolicy = `# VeilWarden OPA policy
#
# This policy controls which HTTP requests are allowed through the proxy.
# See: https://www.openpolicyagent.org/docs/latest/policy-language/

package veilwarden.authz

import rego.v1

# Default: allow all requests (change to false for stricter control)
default allow := true

# Example: Allow specific API hosts
# allow if {
#     input.host == "api.anthropic.com"
# }

# Example: Allow only GET and POST methods
# allow if {
#     input.method in ["GET", "POST", "CONNECT"]
# }

# Example: Block DELETE operations
# allow := false if {
#     input.method == "DELETE"
# }
`

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize VeilWarden configuration in current directory",
	Long: `Create .veilwarden directory with example configuration and policies.

This command creates:
  - .veilwarden/config.yaml (route and sandbox configuration)
  - .veilwarden/policies/allow.rego (example OPA policy)

The config is auto-discovered when running veil from this directory or any subdirectory.

Use --global to create in ~/.veilwarden instead (fallback location).`,
	RunE: runInit,
}

var (
	initConfigDir string
	initGlobal    bool
)

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().StringVar(&initConfigDir, "config-dir", "", "Configuration directory to create (default: .veilwarden)")
	initCmd.Flags().BoolVar(&initGlobal, "global", false, "Create in ~/.veilwarden instead of current directory")
}

func runInit(cmd *cobra.Command, args []string) error {
	// Determine config directory
	var configDir string
	if initConfigDir != "" {
		configDir = warden.ExpandPath(initConfigDir)
	} else if initGlobal {
		configDir = warden.ExpandPath("~/.veilwarden")
	} else {
		configDir = ".veilwarden"
	}

	// Create directory structure
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	policiesDir := filepath.Join(configDir, "policies")
	if err := os.MkdirAll(policiesDir, 0o755); err != nil {
		return fmt.Errorf("failed to create policies directory: %w", err)
	}

	// Write config file
	configPath := filepath.Join(configDir, "config.yaml")
	if err := writeFileIfNotExists(configPath, exampleConfig); err != nil {
		return err
	}

	// Write example policy
	policyPath := filepath.Join(policiesDir, "allow.rego")
	if err := writeFileIfNotExists(policyPath, examplePolicy); err != nil {
		return err
	}

	fmt.Printf("Created configuration directory: %s\n", configDir)
	fmt.Printf("  config.yaml - routes and sandbox settings\n")
	fmt.Printf("  policies/allow.rego - OPA policy (optional)\n")
	fmt.Println("\nNext steps:")
	fmt.Println("  1. Edit config.yaml with your API routes")
	fmt.Println("  2. Set environment variables for secrets (e.g., ANTHROPIC_API_KEY)")
	fmt.Println("  3. Run: veil exec -- <your-command>")

	return nil
}

func writeFileIfNotExists(path, content string) error {
	if _, err := os.Stat(path); err == nil {
		fmt.Printf("⊘ Skipped (already exists): %s\n", path)
		return nil
	}

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}

	return nil
}
