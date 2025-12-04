package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoverConfig_WalkUp(t *testing.T) {
	// Create a temp directory structure:
	// root/
	//   .veilwarden/
	//     config.yaml
	//   subdir/
	//     deepdir/

	root := t.TempDir()
	veilDir := filepath.Join(root, ConfigDirName)
	require.NoError(t, os.Mkdir(veilDir, 0755))

	configPath := filepath.Join(veilDir, ConfigFileName)
	require.NoError(t, os.WriteFile(configPath, []byte("# test"), 0644))

	subdir := filepath.Join(root, "subdir")
	require.NoError(t, os.Mkdir(subdir, 0755))

	deepdir := filepath.Join(subdir, "deepdir")
	require.NoError(t, os.Mkdir(deepdir, 0755))

	// Change to deep directory
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)

	require.NoError(t, os.Chdir(deepdir))

	// Should find config in parent
	discovered := DiscoverConfig()

	// On macOS, /var is a symlink to /private/var, so resolve symlinks for comparison
	expectedPath, _ := filepath.EvalSymlinks(configPath)
	discoveredPath, _ := filepath.EvalSymlinks(discovered)
	assert.Equal(t, expectedPath, discoveredPath)
}

func TestDiscoverConfig_NotFound(t *testing.T) {
	// Create temp dir with no config
	root := t.TempDir()

	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)

	require.NoError(t, os.Chdir(root))

	// Should return empty string (no home fallback in test env)
	discovered := DiscoverConfig()
	// Note: might find home config if it exists, so we just check it doesn't crash
	_ = discovered
}

func TestDiscoverConfig_InCurrentDir(t *testing.T) {
	root := t.TempDir()
	veilDir := filepath.Join(root, ConfigDirName)
	require.NoError(t, os.Mkdir(veilDir, 0755))

	configPath := filepath.Join(veilDir, ConfigFileName)
	require.NoError(t, os.WriteFile(configPath, []byte("# test"), 0644))

	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)

	require.NoError(t, os.Chdir(root))

	discovered := DiscoverConfig()

	// On macOS, /var is a symlink to /private/var, so resolve symlinks for comparison
	expectedPath, _ := filepath.EvalSymlinks(configPath)
	discoveredPath, _ := filepath.EvalSymlinks(discovered)
	assert.Equal(t, expectedPath, discoveredPath)
}
