package main

import (
	"fmt"
	"os"
	"time"

	"veilwarden/internal/doppler"
	"veilwarden/internal/proxy"
)

// buildSecretStore creates either a Doppler store or falls back to environment variables.
// Logic:
// - If cfg.Doppler exists AND DOPPLER_TOKEN env var is set:
//   - Parse cache TTL (default to 5 minutes if not set)
//   - Create doppler.NewStore() with options from config
//
// - Else:
//   - Load secrets from environment based on routes (existing logic from exec.go)
//   - Return proxy.NewMemorySecretStore(secrets)
func buildSecretStore(cfg *veilConfig) (proxy.SecretStore, error) {
	// Check if Doppler is configured and token is available
	dopplerToken := os.Getenv("DOPPLER_TOKEN")
	if cfg.Doppler != nil && dopplerToken != "" {
		// Parse cache TTL, default to 5 minutes if not set
		cacheTTL := 5 * time.Minute
		if cfg.Doppler.CacheTTL != "" {
			var err error
			cacheTTL, err = time.ParseDuration(cfg.Doppler.CacheTTL)
			if err != nil {
				return nil, fmt.Errorf("invalid doppler.cache_ttl: %w", err)
			}
		}

		// Create Doppler store with options from config
		baseURL := os.Getenv("DOPPLER_API_URL")
		if baseURL == "" {
			baseURL = "https://api.doppler.com"
		}

		return doppler.NewStore(&doppler.Options{
			Token:    dopplerToken,
			BaseURL:  baseURL,
			Project:  cfg.Doppler.Project,
			Config:   cfg.Doppler.Config,
			CacheTTL: cacheTTL,
			Timeout:  5 * time.Second,
		}), nil
	}

	// Fallback: Load secrets from environment based on route configurations
	secrets := make(map[string]string)
	for _, route := range cfg.Routes {
		if route.SecretID != "" {
			if val := os.Getenv(route.SecretID); val != "" {
				secrets[route.SecretID] = val
			}
		}
	}

	return proxy.NewMemorySecretStore(secrets), nil
}
