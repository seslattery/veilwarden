package env

import "strings"

// BuildProxyEnv creates an environment for the child process with:
// - Secret-like variables filtered out (unless in passthrough list)
// - Proxy configuration added
// - CA certificate paths set for various tools
func BuildProxyEnv(parentEnv []string, proxyURL, caCertPath string, envPassthrough []string) []string {
	env := make([]string, 0, len(parentEnv)+15)

	// Build passthrough set for O(1) lookup
	passthroughSet := make(map[string]bool)
	for _, key := range envPassthrough {
		passthroughSet[strings.ToUpper(key)] = true
	}

	// Copy parent env, filtering out secrets and proxy vars
	for _, e := range parentEnv {
		key := strings.SplitN(e, "=", 2)[0]
		upper := strings.ToUpper(key)
		lower := strings.ToLower(key)

		// Always strip proxy-related vars (we set our own)
		if strings.HasPrefix(lower, "http_proxy") ||
			strings.HasPrefix(lower, "https_proxy") ||
			strings.Contains(lower, "_ca_") {
			continue
		}

		// Check if explicitly allowed via passthrough
		if passthroughSet[upper] {
			env = append(env, e)
			continue
		}

		// Strip vars that look like secrets
		if LooksLikeSecret(key) {
			continue
		}

		env = append(env, e)
	}

	// Add proxy configuration
	env = append(env,
		// Standard proxy env vars (both cases for compatibility)
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,

		// CA certificate paths for various tools
		"REQUESTS_CA_BUNDLE="+caCertPath,  // Python requests
		"SSL_CERT_FILE="+caCertPath,       // Go, curl
		"NODE_EXTRA_CA_CERTS="+caCertPath, // Node.js
		"CURL_CA_BUNDLE="+caCertPath,      // curl (alternate)
		"PIP_CERT="+caCertPath,            // pip
		"HTTPLIB2_CA_CERTS="+caCertPath,   // Python httplib2
		"AWS_CA_BUNDLE="+caCertPath,       // AWS CLI

		// VeilWarden-specific
		"VEILWARDEN_PROXY_URL="+proxyURL,
	)

	return env
}
