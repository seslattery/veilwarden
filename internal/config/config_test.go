package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_WithDoppler(t *testing.T) {
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

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
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

func TestLoad_WithoutDoppler(t *testing.T) {
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

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Doppler != nil {
		t.Errorf("Expected nil Doppler config, got %+v", cfg.Doppler)
	}
}

func TestLoad_DopplerValidation(t *testing.T) {
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

			_, err := Load(configPath)

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

func TestLoad_DopplerCacheTTLParsing(t *testing.T) {
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

			cfg, err := Load(configPath)
			if err != nil {
				t.Fatalf("Load failed: %v", err)
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

func TestLoad_WithSandbox(t *testing.T) {
	configYAML := `
routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

sandbox:
  enabled: true
  backend: srt
  working_dir: /workspace
  allowed_write_paths:
    - /workspace
    - /tmp/data
  denied_read_paths:
    - ~/.ssh
    - ~/.aws
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(configYAML), 0644)
	require.NoError(t, err)

	cfg, err := Load(configPath)
	require.NoError(t, err)

	require.NotNil(t, cfg.Sandbox)
	assert.True(t, cfg.Sandbox.Enabled)
	assert.Equal(t, "srt", cfg.Sandbox.Backend)
	assert.Equal(t, "/workspace", cfg.Sandbox.WorkingDir)

	require.Len(t, cfg.Sandbox.AllowedWritePaths, 2)
	assert.Equal(t, "/workspace", cfg.Sandbox.AllowedWritePaths[0])
	assert.Equal(t, "/tmp/data", cfg.Sandbox.AllowedWritePaths[1])

	require.Len(t, cfg.Sandbox.DeniedReadPaths, 2)
	assert.Equal(t, "~/.ssh", cfg.Sandbox.DeniedReadPaths[0])
	assert.Equal(t, "~/.aws", cfg.Sandbox.DeniedReadPaths[1])
}

func TestLoad_WithoutSandbox(t *testing.T) {
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

	cfg, err := Load(configPath)
	require.NoError(t, err)

	assert.Nil(t, cfg.Sandbox)
}

func TestLoad_SandboxValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "missing backend",
			yaml: `
routes:
  - host: api.example.com
    secret_id: KEY
    header_name: Authorization
    header_value_template: "{{secret}}"
sandbox:
  enabled: true
`,
			wantErr: "sandbox.backend is required",
		},
		{
			name: "invalid backend",
			yaml: `
routes:
  - host: api.example.com
    secret_id: KEY
    header_name: Authorization
    header_value_template: "{{secret}}"
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

			_, err = Load(configPath)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestLoad_RouteValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "empty host",
			yaml: `routes:
  - host: ""
    secret_id: MY_SECRET
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"`,
			wantErr: "host is required",
		},
		{
			name: "empty secret_id",
			yaml: `routes:
  - host: api.example.com
    secret_id: ""
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"`,
			wantErr: "secret_id is required",
		},
		{
			name: "empty header_name",
			yaml: `routes:
  - host: api.example.com
    secret_id: MY_SECRET
    header_name: ""
    header_value_template: "Bearer {{secret}}"`,
			wantErr: "header_name is required",
		},
		{
			name: "missing secret placeholder",
			yaml: `routes:
  - host: api.example.com
    secret_id: MY_SECRET
    header_name: Authorization
    header_value_template: "Bearer token"`,
			wantErr: "must contain {{secret}}",
		},
		{
			name: "valid config",
			yaml: `routes:
  - host: api.example.com
    secret_id: MY_SECRET
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"`,
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.CreateTemp("", "veil-config-*.yaml")
			require.NoError(t, err)
			defer os.Remove(f.Name())

			_, err = f.WriteString(tt.yaml)
			require.NoError(t, err)
			f.Close()

			_, err = Load(f.Name())
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
