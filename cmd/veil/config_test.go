package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadVeilConfig_WithDoppler(t *testing.T) {
	// Create a temporary config file with Doppler section
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	configContent := `routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

doppler:
  project: my-project
  config: dev
  cache_ttl: 10m
`

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := loadVeilConfig(configPath)
	if err != nil {
		t.Fatalf("loadVeilConfig failed: %v", err)
	}

	if cfg.Doppler == nil {
		t.Fatal("Expected Doppler config, got nil")
	}

	if cfg.Doppler.Project != "my-project" {
		t.Errorf("Expected project 'my-project', got '%s'", cfg.Doppler.Project)
	}

	if cfg.Doppler.Config != "dev" {
		t.Errorf("Expected config 'dev', got '%s'", cfg.Doppler.Config)
	}

	if cfg.Doppler.CacheTTL != "10m" {
		t.Errorf("Expected cache_ttl '10m', got '%s'", cfg.Doppler.CacheTTL)
	}
}

func TestLoadVeilConfig_WithoutDoppler(t *testing.T) {
	// Create a temporary config file without Doppler section
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	configContent := `routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := loadVeilConfig(configPath)
	if err != nil {
		t.Fatalf("loadVeilConfig failed: %v", err)
	}

	if cfg.Doppler != nil {
		t.Errorf("Expected nil Doppler config, got %+v", cfg.Doppler)
	}
}

func TestLoadVeilConfig_DopplerDefaults(t *testing.T) {
	// Test that defaults are applied when optional fields are missing
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	configContent := `routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

doppler:
  project: my-project
  config: dev
`

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := loadVeilConfig(configPath)
	if err != nil {
		t.Fatalf("loadVeilConfig failed: %v", err)
	}

	if cfg.Doppler == nil {
		t.Fatal("Expected Doppler config, got nil")
	}

	// cache_ttl should be empty, defaults will be applied later
	if cfg.Doppler.CacheTTL != "" {
		t.Errorf("Expected empty cache_ttl, got '%s'", cfg.Doppler.CacheTTL)
	}
}

func TestLoadVeilConfig_DopplerValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid doppler config",
			config: `routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

doppler:
  project: my-project
  config: dev
`,
			expectError: false,
		},
		{
			name: "missing project",
			config: `routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

doppler:
  config: dev
`,
			expectError: true,
			errorMsg:    "doppler.project is required",
		},
		{
			name: "missing config",
			config: `routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

doppler:
  project: my-project
`,
			expectError: true,
			errorMsg:    "doppler.config is required",
		},
		{
			name: "invalid cache_ttl",
			config: `routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

doppler:
  project: my-project
  config: dev
  cache_ttl: invalid
`,
			expectError: true,
			errorMsg:    "invalid doppler.cache_ttl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			configPath := filepath.Join(tempDir, "config.yaml")

			if err := os.WriteFile(configPath, []byte(tt.config), 0600); err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			_, err := loadVeilConfig(configPath)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errorMsg)
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			}
		})
	}
}

func TestLoadVeilConfig_DopplerCacheTTLParsing(t *testing.T) {
	tests := []struct {
		name     string
		cacheTTL string
		expected time.Duration
	}{
		{"5 minutes", "5m", 5 * time.Minute},
		{"1 hour", "1h", 1 * time.Hour},
		{"30 seconds", "30s", 30 * time.Second},
		{"2 hours 30 minutes", "2h30m", 2*time.Hour + 30*time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			configPath := filepath.Join(tempDir, "config.yaml")

			configContent := `routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

doppler:
  project: my-project
  config: dev
  cache_ttl: ` + tt.cacheTTL + `
`

			if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			cfg, err := loadVeilConfig(configPath)
			if err != nil {
				t.Fatalf("loadVeilConfig failed: %v", err)
			}

			if cfg.Doppler == nil {
				t.Fatal("Expected Doppler config, got nil")
			}

			if cfg.Doppler.CacheTTL != tt.cacheTTL {
				t.Errorf("Expected cache_ttl '%s', got '%s'", tt.cacheTTL, cfg.Doppler.CacheTTL)
			}

			// Verify it can be parsed as a duration
			parsed, err := time.ParseDuration(cfg.Doppler.CacheTTL)
			if err != nil {
				t.Errorf("Failed to parse cache_ttl '%s': %v", cfg.Doppler.CacheTTL, err)
			}

			if parsed != tt.expected {
				t.Errorf("Expected parsed duration %v, got %v", tt.expected, parsed)
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestLoadVeilConfig_WithSandbox(t *testing.T) {
	configYAML := `
routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

sandbox:
  enabled: true
  backend: anthropic
  working_dir: /workspace
  allowed_write_paths:
    - /workspace
    - /tmp/data
  denied_read_paths:
    - ~/.ssh
    - ~/.aws
`

	// Write temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(configYAML), 0644)
	require.NoError(t, err)

	// Load config
	cfg, err := loadVeilConfig(configPath)
	require.NoError(t, err)

	// Verify sandbox config loaded
	require.NotNil(t, cfg.Sandbox)
	assert.True(t, cfg.Sandbox.Enabled)
	assert.Equal(t, "anthropic", cfg.Sandbox.Backend)
	assert.Equal(t, "/workspace", cfg.Sandbox.WorkingDir)

	// Verify path lists
	require.Len(t, cfg.Sandbox.AllowedWritePaths, 2)
	assert.Equal(t, "/workspace", cfg.Sandbox.AllowedWritePaths[0])
	assert.Equal(t, "/tmp/data", cfg.Sandbox.AllowedWritePaths[1])

	require.Len(t, cfg.Sandbox.DeniedReadPaths, 2)
	assert.Equal(t, "~/.ssh", cfg.Sandbox.DeniedReadPaths[0])
	assert.Equal(t, "~/.aws", cfg.Sandbox.DeniedReadPaths[1])
}

func TestLoadVeilConfig_WithoutSandbox(t *testing.T) {
	configYAML := `
routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(configYAML), 0644)
	require.NoError(t, err)

	cfg, err := loadVeilConfig(configPath)
	require.NoError(t, err)

	// Sandbox should be nil when not configured
	assert.Nil(t, cfg.Sandbox)
}

func TestLoadVeilConfig_SandboxValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "missing backend",
			yaml: `
sandbox:
  enabled: true
`,
			wantErr: "sandbox.backend is required",
		},
		{
			name: "invalid backend",
			yaml: `
sandbox:
  enabled: true
  backend: invalid-backend
`,
			wantErr: "unknown sandbox backend",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			err := os.WriteFile(configPath, []byte(tt.yaml), 0644)
			require.NoError(t, err)

			_, err = loadVeilConfig(configPath)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
