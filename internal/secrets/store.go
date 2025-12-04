package secrets

import (
	"fmt"
	"os"
	"time"

	"veilwarden/internal/config"
	"veilwarden/internal/doppler"
	"veilwarden/internal/proxy"
)

// NewStore creates a secret store based on configuration.
// If Doppler is configured and DOPPLER_TOKEN is set, returns a Doppler store.
// Otherwise, returns a memory store populated from environment variables.
func NewStore(cfg *config.Config) (proxy.SecretStore, error) {
	// Check if Doppler is configured and token is available
	dopplerToken := os.Getenv("DOPPLER_TOKEN")
	if cfg.Doppler != nil && dopplerToken != "" {
		return newDopplerStore(cfg.Doppler, dopplerToken)
	}

	// Fallback: Load secrets from environment based on route configurations
	return newEnvStore(cfg.Routes), nil
}

func newDopplerStore(dopplerCfg *config.DopplerEntry, token string) (proxy.SecretStore, error) {
	// Parse cache TTL, default to 5 minutes if not set
	cacheTTL := 5 * time.Minute
	if dopplerCfg.CacheTTL != "" {
		var err error
		cacheTTL, err = time.ParseDuration(dopplerCfg.CacheTTL)
		if err != nil {
			return nil, fmt.Errorf("invalid doppler.cache_ttl: %w", err)
		}
	}

	// Get base URL from env or use default
	baseURL := os.Getenv("DOPPLER_API_URL")
	if baseURL == "" {
		baseURL = "https://api.doppler.com"
	}

	return doppler.NewStore(&doppler.Options{
		Token:    token,
		BaseURL:  baseURL,
		Project:  dopplerCfg.Project,
		Config:   dopplerCfg.Config,
		CacheTTL: cacheTTL,
		Timeout:  5 * time.Second,
	}), nil
}

func newEnvStore(routes []config.RouteEntry) proxy.SecretStore {
	secrets := make(map[string]string)
	for _, route := range routes {
		if route.SecretID != "" {
			if val := os.Getenv(route.SecretID); val != "" {
				secrets[route.SecretID] = val
			}
		}
	}
	return proxy.NewMemorySecretStore(secrets)
}
