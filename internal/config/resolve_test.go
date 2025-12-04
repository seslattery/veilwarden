package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/seslattery/veilwarden/pkg/warden"
)

func TestLoad_ResolvesRelativePaths(t *testing.T) {
	// Create a config with relative paths
	configYAML := `
policy:
  engine: opa
  policy_path: ./policies
  decision_path: test/allow

sandbox:
  enabled: true
  backend: auto
  working_dir: ./workspace
  allowed_write_paths:
    - ./data
    - /absolute/path
    - ~/home/path
  denied_read_paths:
    - ../parent
    - ~/.ssh
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(configYAML), 0644))

	cfg, err := Load(configPath)
	require.NoError(t, err)

	// Policy path should be resolved relative to config dir
	assert.Equal(t, filepath.Join(tmpDir, "policies"), cfg.Policy.PolicyPath)

	// Sandbox working_dir should be resolved
	assert.Equal(t, filepath.Join(tmpDir, "workspace"), cfg.Sandbox.WorkingDir)

	// Relative write paths should be resolved
	assert.Equal(t, filepath.Join(tmpDir, "data"), cfg.Sandbox.AllowedWritePaths[0])
	// Absolute paths stay absolute
	assert.Equal(t, "/absolute/path", cfg.Sandbox.AllowedWritePaths[1])
	// Home paths are expanded
	assert.Equal(t, warden.ExpandPath("~/home/path"), cfg.Sandbox.AllowedWritePaths[2])

	// Parent-relative paths are resolved
	assert.Equal(t, filepath.Join(filepath.Dir(tmpDir), "parent"), cfg.Sandbox.DeniedReadPaths[0])
	// Home paths in denied are expanded
	assert.Equal(t, warden.ExpandPath("~/.ssh"), cfg.Sandbox.DeniedReadPaths[1])
}

func TestLoad_WorkingDirOmitted_UsesCwd(t *testing.T) {
	configYAML := `
sandbox:
  enabled: true
  backend: auto
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(configYAML), 0644))

	cfg, err := Load(configPath)
	require.NoError(t, err)

	// WorkingDir should be empty (will use cwd at runtime)
	assert.Empty(t, cfg.Sandbox.WorkingDir)
}

func TestLoad_ConfigDir(t *testing.T) {
	configYAML := `
sandbox:
  enabled: true
  backend: auto
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(configYAML), 0644))

	cfg, err := Load(configPath)
	require.NoError(t, err)

	assert.Equal(t, tmpDir, cfg.ConfigDir())
}

func TestDefault_HasCorrectValues(t *testing.T) {
	cfg := Default()

	require.NotNil(t, cfg.Sandbox)
	assert.True(t, cfg.Sandbox.Enabled)
	assert.Equal(t, "auto", cfg.Sandbox.Backend)
	assert.True(t, cfg.Sandbox.EnablePTY)
}

func TestApplyDefaults_FillsMissingValues(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyDefaults()

	require.NotNil(t, cfg.Sandbox)
	assert.True(t, cfg.Sandbox.Enabled)
	assert.Equal(t, "auto", cfg.Sandbox.Backend)
	assert.True(t, cfg.Sandbox.EnablePTY)
}

func TestApplyDefaults_PreservesExistingValues(t *testing.T) {
	cfg := &Config{
		Sandbox: &SandboxEntry{
			Enabled: false, // Explicitly disabled
			Backend: "srt",
		},
	}
	cfg.ApplyDefaults()

	assert.False(t, cfg.Sandbox.Enabled) // Should stay false
	assert.Equal(t, "srt", cfg.Sandbox.Backend)
}

func TestApplyDefaults_FillsEmptyBackend(t *testing.T) {
	cfg := &Config{
		Sandbox: &SandboxEntry{
			Enabled: true,
			Backend: "", // Empty
		},
	}
	cfg.ApplyDefaults()

	assert.Equal(t, "auto", cfg.Sandbox.Backend)
}
