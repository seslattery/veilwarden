package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidatePaths checks if all paths in the config are valid
func ValidatePaths(cfg *Config) error {
	// Validate allowed write paths exist
	for i, p := range cfg.AllowedWritePaths {
		expanded := expandPath(p)
		if err := validatePathExists(expanded); err != nil {
			return fmt.Errorf("allowed_write_paths[%d] (%s): %w", i, p, err)
		}
	}

	// Validate allowed read paths exist (if specified)
	for i, p := range cfg.AllowedReadPaths {
		expanded := expandPath(p)
		if err := validatePathExists(expanded); err != nil {
			return fmt.Errorf("allowed_read_paths[%d] (%s): %w", i, p, err)
		}
	}

	// Note: We don't validate denied_read_paths exist because they may be
	// paths we want to block even if they don't exist on this system

	return nil
}

// validatePathExists checks if a path exists
func validatePathExists(path string) error {
	if path == "" {
		return fmt.Errorf("path is empty")
	}

	// Check if path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", path)
	}

	return nil
}

// WarnSensitiveWritePaths prints warnings if sensitive directories are writable
func WarnSensitiveWritePaths(paths []string) {
	for _, p := range paths {
		expanded := expandPath(p)
		if isSensitivePath(expanded) {
			fmt.Fprintf(os.Stderr, "WARNING: Allowing writes to sensitive directory: %s\n", expanded)
			fmt.Fprintf(os.Stderr, "This gives the sandboxed process write access to sensitive files.\n")
			fmt.Fprintf(os.Stderr, "Only proceed if you trust this command completely.\n\n")
		}
	}
}

// isSensitivePath returns true if the path is a sensitive system directory
func isSensitivePath(path string) bool {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/nonexistent" // Fallback if can't get home
	}

	sensitive := []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".config", "gcloud"),
		filepath.Join(home, ".azure"),
		filepath.Join(home, ".doppler"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".kube"),
		filepath.Join(home, ".docker"),
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
	}

	// Expand path for comparison
	expanded := expandPath(path)

	for _, s := range sensitive {
		// Check if path equals or is subdirectory of sensitive path
		if expanded == s || strings.HasPrefix(expanded, s+string(filepath.Separator)) {
			return true
		}
		// Also check if sensitive path is subdirectory of the given path
		// (e.g., if allowing writes to ~ which includes ~/.ssh)
		if strings.HasPrefix(s, expanded+string(filepath.Separator)) {
			return true
		}
	}

	return false
}

// SuggestDeniedReadPaths returns suggested paths to deny reading based on common sensitive locations
func SuggestDeniedReadPaths() []string {
	return DefaultDeniedReadPaths()
}
