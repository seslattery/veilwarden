package config

import (
	"os"
	"path/filepath"

	"github.com/seslattery/veilwarden/pkg/warden"
)

const (
	// ConfigDirName is the directory name for veilwarden config.
	ConfigDirName = ".veilwarden"
	// ConfigFileName is the config file name within the config directory.
	ConfigFileName = "config.yaml"
)

// DiscoverConfig finds the config file using walk-up discovery.
// Search order:
//  1. Walk up from cwd looking for .veilwarden/config.yaml
//  2. Fall back to ~/.veilwarden/config.yaml
//
// Returns the path to the config file, or empty string if not found.
func DiscoverConfig() string {
	// Start from current working directory
	cwd, err := os.Getwd()
	if err != nil {
		// Can't get cwd, try home directory fallback
		return homeConfigPath()
	}

	// Walk up looking for .veilwarden/config.yaml
	dir := cwd
	for {
		configPath := filepath.Join(dir, ConfigDirName, ConfigFileName)
		if fileExists(configPath) {
			return configPath
		}

		// Move to parent directory
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root, stop
			break
		}
		dir = parent
	}

	// Fall back to home directory
	homePath := homeConfigPath()
	if fileExists(homePath) {
		return homePath
	}

	return ""
}

// homeConfigPath returns the path to ~/.veilwarden/config.yaml
func homeConfigPath() string {
	return warden.ExpandPath("~/" + ConfigDirName + "/" + ConfigFileName)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
