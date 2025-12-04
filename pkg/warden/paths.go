package warden

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ExpandPath expands ~ to home directory.
// This is the canonical path expansion function - use this everywhere.
func ExpandPath(path string) string {
	if path == "" {
		return path
	}

	// Handle ~ expansion
	if path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return home
	}

	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		path = filepath.Join(home, path[2:])
	}

	return path
}

// ExpandPathWithSymlinks expands path and resolves symlinks.
// Use for seatbelt rules where /var -> /private/var matters.
func ExpandPathWithSymlinks(path string) string {
	expanded := ExpandPath(path)
	if resolved, err := filepath.EvalSymlinks(expanded); err == nil {
		return resolved
	}
	return expanded
}

// expandHome is an alias for ExpandPathWithSymlinks for seatbelt compatibility.
// Deprecated: Use ExpandPath or ExpandPathWithSymlinks directly.
func expandHome(path string) string {
	return ExpandPathWithSymlinks(path)
}

// isGlob returns true if the path contains glob metacharacters.
// Note: We only allow * and ? for safety (not [] character classes).
func isGlob(path string) bool {
	return strings.ContainsAny(path, "*?")
}

// isSensitivePath returns true if the path is a sensitive system location.
func isSensitivePath(path string) bool {
	// Special case: root directory itself
	if path == "/" {
		return true
	}

	// Root paths (these and their subdirectories are sensitive)
	rootPaths := []string{
		"/etc", "/usr", "/var", "/bin", "/sbin", "/lib",
		"/root", "/home",
	}

	for _, s := range rootPaths {
		if path == s || strings.HasPrefix(path, s+"/") {
			return true
		}
	}

	// Home dotfiles (specific subdirectories in home are sensitive)
	home, _ := os.UserHomeDir()
	if home != "" {
		homeDotfiles := []string{
			filepath.Join(home, ".ssh"),
			filepath.Join(home, ".aws"),
			filepath.Join(home, ".gnupg"),
			filepath.Join(home, ".kube"),
			filepath.Join(home, ".docker"),
		}

		for _, s := range homeDotfiles {
			if path == s || strings.HasPrefix(path, s+"/") {
				return true
			}
		}
	}

	return false
}

// validatePathSafety checks if a path is safe for use in sandbox rules.
func validatePathSafety(path string, isAllowRule bool) error {
	// Block path traversal
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal not allowed: %s", path)
	}

	// Block root wildcards
	if path == "/*" || path == "/**" {
		return fmt.Errorf("root wildcard not allowed: %s", path)
	}

	// Block regex metacharacters that could escape seatbelt rules
	// Seatbelt uses POSIX regex, so these are dangerous:
	regexMeta := []string{
		"(?", "\\d", "\\w", "\\s", "\\b", // Regex escapes
		"{", "}",                          // Quantifiers
		"|",                               // Alternation
		"^", "$",                          // Anchors
		"+",                               // Quantifier
		"[", "]",                          // Character classes
	}
	for _, s := range regexMeta {
		if strings.Contains(path, s) {
			return fmt.Errorf("regex metacharacter not allowed in path: %s", s)
		}
	}

	// Extra restrictions for allow rules (write paths)
	if isAllowRule && isGlob(path) {
		// No recursive globs in allow rules
		if strings.Contains(path, "**") {
			return fmt.Errorf("** not allowed in write paths: %s", path)
		}

		// Must have at least 2 directory levels
		prefix := extractLiteralPrefix(path)
		if strings.Count(prefix, "/") < 2 {
			return fmt.Errorf("allow glob too broad, need at least 2 directory levels: %s", path)
		}

		// Cannot be a sensitive path
		if isSensitivePath(prefix) {
			return fmt.Errorf("cannot allow writes to sensitive path: %s", path)
		}
	}

	return nil
}

// extractLiteralPrefix returns the non-glob prefix of a path.
func extractLiteralPrefix(path string) string {
	for i, c := range path {
		if c == '*' || c == '?' || c == '[' {
			// Return up to last slash before glob
			lastSlash := strings.LastIndex(path[:i], "/")
			if lastSlash >= 0 {
				return path[:lastSlash]
			}
			return ""
		}
	}
	return path
}
