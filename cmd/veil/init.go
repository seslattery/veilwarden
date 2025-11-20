package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// Embedded example files
var exampleConfig = `# VeilWarden laptop configuration
# Copy to ~/.veilwarden/config.yaml and customize

routes:
  # OpenAI API
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

  # Anthropic API
  - host: api.anthropic.com
    secret_id: ANTHROPIC_API_KEY
    header_name: x-api-key
    header_value_template: "{{secret}}"

  # GitHub API
  - host: api.github.com
    secret_id: GITHUB_TOKEN
    header_name: Authorization
    header_value_template: "token {{secret}}"

# Policy configuration
policy:
  enabled: true
  engine: opa
  policy_path: ~/.veilwarden/policies
  decision_path: veilwarden/authz/allow
`

var examplePolicy = `# VeilWarden laptop policy example
# Copy to ~/.veilwarden/policies/ and customize

package veilwarden.authz

# Default deny all requests
default allow := false

# Allow OpenAI API
allow if {
    input.upstream_host == "api.openai.com"
    input.method in ["GET", "POST"]
}

# Allow Anthropic API
allow if {
    input.upstream_host == "api.anthropic.com"
    input.method in ["GET", "POST"]
}

# Allow GitHub API (read-only)
allow if {
    input.upstream_host == "api.github.com"
    input.method in ["GET", "HEAD"]
}

# Block DELETE operations globally
deny if {
    input.method == "DELETE"
}
`

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize VeilWarden configuration directory",
	Long: `Create ~/.veilwarden directory with example configuration and policies.

This command creates:
  - ~/.veilwarden/config.yaml (route configuration)
  - ~/.veilwarden/policies/allow.rego (example OPA policy)

You can customize these files for your use case.`,
	RunE: runInit,
}

var initConfigDir string

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().StringVar(&initConfigDir, "config-dir", "~/.veilwarden", "Configuration directory to create")
}

func runInit(cmd *cobra.Command, args []string) error {
	// Expand home directory
	configDir := expandHomeDir(initConfigDir)

	// Create directory structure
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	policiesDir := filepath.Join(configDir, "policies")
	if err := os.MkdirAll(policiesDir, 0755); err != nil {
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

	fmt.Printf("✓ Created configuration directory: %s\n", configDir)
	fmt.Printf("✓ Created config file: %s\n", configPath)
	fmt.Printf("✓ Created example policy: %s\n", policyPath)
	fmt.Println("\nNext steps:")
	fmt.Println("1. Set DOPPLER_TOKEN environment variable")
	fmt.Println("2. Customize config.yaml with your routes")
	fmt.Println("3. Customize policies/*.rego with your policies")
	fmt.Println("4. Run: veil exec -- <your-command>")

	return nil
}

func expandHomeDir(path string) string {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[1:])
		}
	}
	return path
}

func writeFileIfNotExists(path string, content string) error {
	if _, err := os.Stat(path); err == nil {
		fmt.Printf("⊘ Skipped (already exists): %s\n", path)
		return nil
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}

	return nil
}
