// pkg/warden/dangerous_files.go
package warden

import (
	"path/filepath"
	"strings"
)

// DangerousFilePatterns returns seatbelt regex patterns for files that should
// never be writable when dangerous file blocking is enabled.
// These patterns are in seatbelt regex format (POSIX ERE).
func DangerousFilePatterns() []string {
	return []string{
		// Environment files with secrets (.env, .env.local, .env.production, etc.)
		`.*/\.env$`,         // matches any path ending in .env
		`.*/\.env\..*`,      // matches .env.* variants
		`^\.env$`,           // matches literal .env in cwd

		// Package manager credentials
		`.*/\.npmrc$`,
		`^\.npmrc$`,
		`.*/\.pypirc$`,
		`^\.pypirc$`,
		`.*/\.gem/credentials$`,

		// Git hooks (code execution vector)
		`.*/\.git/hooks$`,   // the hooks directory itself
		`.*/\.git/hooks/.*`, // files inside hooks

		// Git config (can set core.hooksPath to execute arbitrary code)
		`.*/\.git/config$`,

		// Docker credentials
		`.*/\.docker/config\.json$`,

		// Cloud provider credentials
		`.*/\.aws/credentials$`,
		`.*/\.azure/credentials$`,
		`.*/\.config/gcloud/credentials\.db$`,
	}
}

// dangerousFiles is a map of literal file names that are dangerous.
var dangerousFiles = map[string]bool{
	".env":        true,
	".npmrc":      true,
	".pypirc":     true,
	"credentials": true,
}

// dangerousDirs is a map of directory names that are dangerous.
var dangerousDirs = map[string]bool{
	"hooks": true, // .git/hooks
}

// IsDangerousPath checks if a path matches dangerous patterns.
func IsDangerousPath(path string) bool {
	// Normalize path
	path = filepath.Clean(path)
	base := filepath.Base(path)
	dir := filepath.Dir(path)

	// Check for .env and .env.* files
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}

	// Check dangerous files
	if dangerousFiles[base] {
		return true
	}

	// Check .git/hooks
	if strings.Contains(path, ".git/hooks") {
		return true
	}

	// Check .git/config
	if strings.HasSuffix(path, ".git/config") {
		return true
	}

	// Check for hooks directory under .git
	if dangerousDirs[base] && strings.HasSuffix(dir, ".git") {
		return true
	}

	return false
}
