package env

import "strings"

// LooksLikeSecret returns true if the env var name matches common secret patterns.
// This is a heuristic to strip credentials that agents shouldn't see.
func LooksLikeSecret(key string) bool {
	upper := strings.ToUpper(key)

	// Common secret suffixes/patterns
	secretPatterns := []string{
		"_KEY",
		"_TOKEN",
		"_SECRET",
		"_PASSWORD",
		"_CREDENTIAL",
		"_CREDENTIALS",
		"_API_KEY",
		"_APIKEY",
		"_AUTH",
		"_PRIVATE",
	}

	for _, pattern := range secretPatterns {
		if strings.Contains(upper, pattern) {
			return true
		}
	}

	// Specific known sensitive vars
	sensitiveVars := map[string]bool{
		"DOPPLER_TOKEN":                   true,
		"AWS_ACCESS_KEY_ID":               true,
		"AWS_SECRET_ACCESS_KEY":           true,
		"AWS_SESSION_TOKEN":               true,
		"GITHUB_TOKEN":                    true,
		"GH_TOKEN":                        true,
		"GITLAB_TOKEN":                    true,
		"NPM_TOKEN":                       true,
		"PYPI_TOKEN":                      true,
		"DOCKER_PASSWORD":                 true,
		"DOCKER_AUTH_CONFIG":              true,
		"KUBECONFIG":                      true,
		"GOOGLE_APPLICATION_CREDENTIALS":  true,
	}

	return sensitiveVars[upper]
}
