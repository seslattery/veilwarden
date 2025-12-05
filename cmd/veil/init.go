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
#routes:
# Example: Anthropic API
# - host: api.anthropic.com
#  secret_id: ANTHROPIC_API_KEY
#  header_name: x-api-key
#  header_value_template: "{{secret}}"

# Example: OpenAI API
# - host: api.openai.com
#   secret_id: OPENAI_API_KEY
#   header_name: Authorization
#   header_value_template: "Bearer {{secret}}"

# Optional: OPA policy for request authorization
policy:
  engine: opa
  policy_path: ./policies # Relative to this config file
  decision_path: veilwarden/authz/allow

# Optional: Fetch secrets from Doppler instead of environment variables
# doppler:
#   project: my-project
#   config: dev

# Sandbox settings
sandbox:
  enabled: true
  backend: auto
  enable_pty: true
  allowed_write_paths:
    - .. # Project directory
    - /tmp
    - /var/tmp
    - ~/.claude.json # Claude Code state
    - ~/.claude # Claude Code data
    - ~/Library/Caches/go-build # Go build cache
    # Reads: explicit extra denies on top of "block all ~/.*"
  denied_read_paths:
    # Home-level secrets (many redundant with your ~/.* rule, but fine to be explicit)
    - ~/.ssh
    - ~/.aws
    - ~/.config/gcloud
    - ~/.azure
    - ~/.kube
    - ~/.docker
    - ~/.doppler
    - ~/.gnupg
    - ~/.password-store
    - ~/.vault-token
    - ~/.netrc
    - ~/.git-credentials
    - ~/.npmrc
    - ~/.pypirc
    - ~/.config/gh # GitHub CLI hosts/tokens
    - ~/.config/hub # Older GitHub tool

    # Non-dot but very sensitive on macOS (outside your ~/.* rule)
    - ~/Library/Keychains
    - /Library/Keychains
    - /System/Library/Keychains

    # Browsers – cookies, sessions, OAuth tokens, etc.
    - ~/Library/Application Support/Google/Chrome
    - ~/Library/Application Support/BraveSoftware
    - ~/Library/Application Support/Microsoft Edge
    - ~/Library/Application Support/Firefox
    - ~/Library/Safari

    # Comms / personal data
    - ~/Library/Mail
    - ~/Library/Messages

    # iCloud / app group containers (lots of auth-y stuff can live here)
    - ~/Library/Group Containers
`

var examplePolicy = `package veilwarden.authz

import rego.v1

default allow := false

llm_hosts := {
  "api.anthropic.com",
  "api.openai.com",
  "generativelanguage.googleapis.com",
}

scm_hosts_ro := {
  "github.com",
  "api.github.com",
  "raw.githubusercontent.com",
  "gitlab.com",
  "api.gitlab.com",
  "bitbucket.org",
  "dev.azure.com",
}

# Future: Hosts where we allow full read/write, from user config
# trusted_rw_hosts := { h | h := input.config.trusted_rw_hosts[_] }

# Future: Hosts where we allow more permissive reads (e.g. GET with body/auth)
# trusted_ro_hosts := { h | h := input.config.trusted_ro_hosts[_] }

method_is_read_only(method) if {
  method == "GET"
}

method_is_read_only(method) if {
  method == "HEAD"
}

has_body if {
  input.body != ""
}

# Future: Check for auth headers when headers are available in input
# has_auth_header if {
#   input.headers["authorization"] != ""
# }
# has_auth_header if {
#   input.headers["x-api-key"] != ""
# }

############################
# Allow rules
############################

# 1) Fully trusted hosts (LLM providers)
allow if {
  input.upstream_host in llm_hosts
}

# Future: Allow configured RW hosts
# allow if {
#   input.upstream_host in trusted_rw_hosts
# }

# 2) Source control + code hosting: read-only, no body
allow if {
  input.upstream_host in scm_hosts_ro
  method_is_read_only(input.method)
  not has_body
}

# Future: Trusted read-only hosts (user-configured)
# allow if {
#   input.upstream_host in trusted_ro_hosts
#   method_is_read_only(input.method)
# }

# 3) Everything else on the Internet:
#    GET/HEAD only, no body
#    Future: also check for no auth headers to prevent credential leakage
allow if {
  not (input.upstream_host in llm_hosts)
  not (input.upstream_host in scm_hosts_ro)
  # Future: not (input.upstream_host in trusted_rw_hosts)
  # Future: not (input.upstream_host in trusted_ro_hosts)

  method_is_read_only(input.method)
  not has_body
  # Future: not has_auth_header
}
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
	fmt.Println("  1. Run: veil <your-command>")
	fmt.Println("  2. (Optional) Edit config.yaml to customize routes and settings")
	fmt.Println("  3. (Optional) Set environment variables for secrets (e.g., ANTHROPIC_API_KEY)")

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
