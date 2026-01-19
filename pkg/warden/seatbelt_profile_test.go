package warden

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateProfile(t *testing.T) {
	cfg := &Config{
		Command:           []string{"python", "agent.py"},
		ProxyAddr:         "127.0.0.1:8080",
		AllowedWritePaths: []string{"/tmp/project"},
		DeniedReadPaths:   []string{"~/.ssh", "~/.aws"},
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	// Check basic structure (standard tier has violation logging by default)
	assert.Contains(t, profile, "(version 1)")
	assert.Contains(t, profile, "(deny default (with message")

	// Check proxy port (only localhost, not 127.0.0.1 due to seatbelt limitations)
	assert.Contains(t, profile, "localhost:8080")

	// Check paths are expanded
	assert.Contains(t, profile, "(deny file-read* (subpath")
	assert.Contains(t, profile, "(allow file-write* (subpath")
}

func TestGenerateProfile_WithGlobs(t *testing.T) {
	cfg := &Config{
		Command:           []string{"echo"},
		ProxyAddr:         "127.0.0.1:8080",
		DeniedReadPaths:   []string{"~/.config/*/credentials"},
		AllowedWritePaths: []string{"/tmp/project/agent-*"},
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	// Globs should be converted to regex
	assert.Contains(t, profile, "(regex #\"")
	assert.Contains(t, profile, "[^/]*") // * -> [^/]*
}

func TestGenerateProfile_PTY(t *testing.T) {
	cfg := &Config{
		Command:   []string{"bash"},
		ProxyAddr: "127.0.0.1:8080",
		EnablePTY: true,
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	assert.Contains(t, profile, "(allow pseudo-tty)")
	assert.Contains(t, profile, "/dev/ptmx")
}

func TestGenerateProfile_NoPTY(t *testing.T) {
	cfg := &Config{
		Command:   []string{"echo"},
		ProxyAddr: "127.0.0.1:8080",
		EnablePTY: false,
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	assert.NotContains(t, profile, "(allow pseudo-tty)")
}

func TestBuildProfileData_StandardTier(t *testing.T) {
	cfg := &Config{
		Command:   []string{"echo"},
		ProxyAddr: "127.0.0.1:8080",
		Tier:      TierStandard,
	}

	data, err := buildProfileData(cfg)
	require.NoError(t, err)

	assert.Equal(t, TierStandard, data.Tier)
	assert.True(t, data.EnableMoveBlocking)
	assert.True(t, data.EnableViolationLogging)
	assert.True(t, data.EnableDotfileProtection)
	assert.False(t, data.AllowAllProcessInfo)
	assert.Len(t, data.MachServices, 14)
}

func TestBuildProfileData_PermissiveTier(t *testing.T) {
	cfg := &Config{
		Command:   []string{"echo"},
		ProxyAddr: "127.0.0.1:8080",
		Tier:      TierPermissive,
	}

	data, err := buildProfileData(cfg)
	require.NoError(t, err)

	assert.Equal(t, TierPermissive, data.Tier)
	assert.False(t, data.EnableMoveBlocking)
	assert.False(t, data.EnableViolationLogging)
	assert.False(t, data.EnableDotfileProtection)
	assert.True(t, data.AllowAllProcessInfo)
	assert.Len(t, data.MachServices, 23)
}

func TestGenerateProfile_StandardTierViolationLogging(t *testing.T) {
	cfg := &Config{
		Command:   []string{"echo"},
		ProxyAddr: "127.0.0.1:8080",
		Tier:      TierStandard,
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	// Standard tier should have violation logging
	assert.Contains(t, profile, "(deny default (with message")
}

func TestGenerateProfile_PermissiveTierNoViolationLogging(t *testing.T) {
	cfg := &Config{
		Command:   []string{"echo"},
		ProxyAddr: "127.0.0.1:8080",
		Tier:      TierPermissive,
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	// Permissive tier should NOT have violation logging
	assert.Contains(t, profile, "(deny default)")
	assert.NotContains(t, profile, "(deny default (with message")
}

func TestGenerateProfile_StandardTierLimitedMachServices(t *testing.T) {
	cfg := &Config{
		Command:   []string{"echo"},
		ProxyAddr: "127.0.0.1:8080",
		Tier:      TierStandard,
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	// Standard tier should NOT have auth services
	assert.NotContains(t, profile, "com.apple.security.agent")
	assert.NotContains(t, profile, "com.apple.accountsd")

	// But should have core services
	assert.Contains(t, profile, "com.apple.fonts")
}

func TestGenerateProfile_PermissiveTierAllMachServices(t *testing.T) {
	cfg := &Config{
		Command:   []string{"echo"},
		ProxyAddr: "127.0.0.1:8080",
		Tier:      TierPermissive,
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	// Permissive tier should have auth services
	assert.Contains(t, profile, "com.apple.security.agent")
	assert.Contains(t, profile, "com.apple.accountsd")
}

func TestGenerateProfile_StandardTierSysctlAllowlist(t *testing.T) {
	cfg := &Config{
		Command:   []string{"echo"},
		ProxyAddr: "127.0.0.1:8080",
		Tier:      TierStandard,
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	// Standard tier should have explicit sysctl allowlist
	assert.Contains(t, profile, "(sysctl-name \"hw.ncpu\")")
}

func TestGenerateProfile_PermissiveTierAllowAllSysctl(t *testing.T) {
	cfg := &Config{
		Command:   []string{"echo"},
		ProxyAddr: "127.0.0.1:8080",
		Tier:      TierPermissive,
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	// Permissive tier should allow all sysctl reads (simple form)
	assert.Contains(t, profile, "(allow sysctl-read)")
}

func TestGenerateProfile_StandardTierProcessInfoRestricted(t *testing.T) {
	cfg := &Config{
		Command:   []string{"echo"},
		ProxyAddr: "127.0.0.1:8080",
		Tier:      TierStandard,
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	// Standard tier should restrict process info to same-sandbox
	assert.Contains(t, profile, "(allow process-info* (target same-sandbox))")
}

func TestGenerateProfile_PermissiveTierProcessInfoAll(t *testing.T) {
	cfg := &Config{
		Command:   []string{"echo"},
		ProxyAddr: "127.0.0.1:8080",
		Tier:      TierPermissive,
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	// Permissive tier should allow all process info
	assert.Contains(t, profile, "(allow process-info*)")
	assert.NotContains(t, profile, "(allow process-info* (target same-sandbox))")
}

func TestGenerateProfile_StandardTierBlocksDangerousFiles(t *testing.T) {
	cfg := &Config{
		Command:   []string{"echo"},
		ProxyAddr: "127.0.0.1:8080",
		Tier:      TierStandard,
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	// Standard tier should block dangerous files
	assert.Contains(t, profile, `(deny file-write* (regex #".*/\.env$"))`)
	assert.Contains(t, profile, `(deny file-write* (regex #".*/\.git/hooks/.*"))`)
	assert.Contains(t, profile, `(deny file-write* (regex #".*/\.git/config$"))`)
	assert.Contains(t, profile, `(deny file-write* (regex #".*/\.npmrc$"))`)
}

func TestGenerateProfile_PermissiveTierBlocksDangerousFilesByDefault(t *testing.T) {
	// Permissive tier with AllowDangerousFiles=false (default) should still block dangerous files
	cfg := &Config{
		Command:             []string{"echo"},
		ProxyAddr:           "127.0.0.1:8080",
		Tier:                TierPermissive,
		AllowDangerousFiles: false, // default
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	// Should have dangerous file denies by default
	assert.Contains(t, profile, `(deny file-write* (regex #".*/\.env$"))`)
	assert.Contains(t, profile, `(deny file-write* (regex #".*/\.git/hooks/.*"))`)
}

func TestGenerateProfile_PermissiveTierAllowsDangerousFilesWhenEnabled(t *testing.T) {
	// Permissive tier with AllowDangerousFiles=true should NOT block dangerous files
	cfg := &Config{
		Command:             []string{"echo"},
		ProxyAddr:           "127.0.0.1:8080",
		Tier:                TierPermissive,
		AllowDangerousFiles: true, // explicitly enabled
	}

	profile, err := generateSeatbeltProfile(cfg)
	require.NoError(t, err)

	// Should NOT have dangerous file denies
	assert.NotContains(t, profile, `(deny file-write* (regex #".*/\.env$"))`)
	assert.NotContains(t, profile, `(deny file-write* (regex #".*/\.git/hooks/.*"))`)
}
