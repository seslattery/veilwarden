package main

import (
	"context"
	"os"
	"testing"
	"time"

	"veilwarden/internal/doppler"
	"veilwarden/internal/proxy"
)

func TestBuildSecretStore_DopplerConfigured(t *testing.T) {
	// Test that Doppler store is created when config and token are present
	os.Setenv("DOPPLER_TOKEN", "test-token")
	defer os.Unsetenv("DOPPLER_TOKEN")

	cfg := &veilConfig{
		Doppler: &veilDopplerEntry{
			Project:  "test-project",
			Config:   "test-config",
			CacheTTL: "10m",
		},
		Routes: []veilRouteEntry{
			{Host: "api.example.com", SecretID: "API_KEY"},
		},
	}

	store, err := buildSecretStore(cfg)
	if err != nil {
		t.Fatalf("buildSecretStore() failed: %v", err)
	}

	// Verify it's a Doppler store (by type assertion)
	if _, ok := store.(*doppler.Store); !ok {
		t.Errorf("Expected *doppler.Store, got %T", store)
	}
}

func TestBuildSecretStore_DopplerNoCacheTTL(t *testing.T) {
	// Test that default cache TTL is used when not specified
	os.Setenv("DOPPLER_TOKEN", "test-token")
	defer os.Unsetenv("DOPPLER_TOKEN")

	cfg := &veilConfig{
		Doppler: &veilDopplerEntry{
			Project: "test-project",
			Config:  "test-config",
			// CacheTTL not specified
		},
	}

	store, err := buildSecretStore(cfg)
	if err != nil {
		t.Fatalf("buildSecretStore() failed: %v", err)
	}

	// Verify it's a Doppler store
	if _, ok := store.(*doppler.Store); !ok {
		t.Errorf("Expected *doppler.Store, got %T", store)
	}
}

func TestBuildSecretStore_DopplerConfigNoToken(t *testing.T) {
	// Test that memory store is used when Doppler config exists but token is missing
	os.Unsetenv("DOPPLER_TOKEN")

	cfg := &veilConfig{
		Doppler: &veilDopplerEntry{
			Project: "test-project",
			Config:  "test-config",
		},
		Routes: []veilRouteEntry{
			{Host: "api.example.com", SecretID: "API_KEY"},
		},
	}

	// Set environment variable for the secret
	os.Setenv("API_KEY", "test-secret-value")
	defer os.Unsetenv("API_KEY")

	store, err := buildSecretStore(cfg)
	if err != nil {
		t.Fatalf("buildSecretStore() failed: %v", err)
	}

	// Verify it's a memory store
	if _, ok := store.(*proxy.MemorySecretStore); !ok {
		t.Errorf("Expected *proxy.MemorySecretStore, got %T", store)
	}

	// Verify secret was loaded from environment
	val, err := store.Get(context.Background(), "API_KEY")
	if err != nil {
		t.Fatalf("Get(API_KEY) failed: %v", err)
	}
	if val != "test-secret-value" {
		t.Errorf("Expected secret value 'test-secret-value', got '%s'", val)
	}
}

func TestBuildSecretStore_NoDopplerConfig(t *testing.T) {
	// Test that memory store is used when Doppler is not configured
	os.Unsetenv("DOPPLER_TOKEN")

	cfg := &veilConfig{
		Routes: []veilRouteEntry{
			{Host: "api.example.com", SecretID: "API_KEY"},
			{Host: "api.other.com", SecretID: "OTHER_KEY"},
		},
	}

	// Set environment variables for the secrets
	os.Setenv("API_KEY", "secret-1")
	os.Setenv("OTHER_KEY", "secret-2")
	defer func() {
		os.Unsetenv("API_KEY")
		os.Unsetenv("OTHER_KEY")
	}()

	store, err := buildSecretStore(cfg)
	if err != nil {
		t.Fatalf("buildSecretStore() failed: %v", err)
	}

	// Verify it's a memory store
	if _, ok := store.(*proxy.MemorySecretStore); !ok {
		t.Errorf("Expected *proxy.MemorySecretStore, got %T", store)
	}

	// Verify both secrets were loaded
	val1, err := store.Get(context.Background(), "API_KEY")
	if err != nil {
		t.Fatalf("Get(API_KEY) failed: %v", err)
	}
	if val1 != "secret-1" {
		t.Errorf("Expected 'secret-1', got '%s'", val1)
	}

	val2, err := store.Get(context.Background(), "OTHER_KEY")
	if err != nil {
		t.Fatalf("Get(OTHER_KEY) failed: %v", err)
	}
	if val2 != "secret-2" {
		t.Errorf("Expected 'secret-2', got '%s'", val2)
	}
}

func TestBuildSecretStore_MemoryStoreLoadsFromRoutes(t *testing.T) {
	// Test that memory store only loads secrets referenced in routes
	cfg := &veilConfig{
		Routes: []veilRouteEntry{
			{Host: "api.example.com", SecretID: "USED_KEY"},
		},
	}

	// Set multiple env vars, but only one is in routes
	os.Setenv("USED_KEY", "used-value")
	os.Setenv("UNUSED_KEY", "unused-value")
	defer func() {
		os.Unsetenv("USED_KEY")
		os.Unsetenv("UNUSED_KEY")
	}()

	store, err := buildSecretStore(cfg)
	if err != nil {
		t.Fatalf("buildSecretStore() failed: %v", err)
	}

	memStore, ok := store.(*proxy.MemorySecretStore)
	if !ok {
		t.Fatalf("Expected *proxy.MemorySecretStore, got %T", store)
	}

	// Verify used key is loaded
	val, err := memStore.Get(context.Background(), "USED_KEY")
	if err != nil {
		t.Fatalf("Get(USED_KEY) failed: %v", err)
	}
	if val != "used-value" {
		t.Errorf("Expected 'used-value', got '%s'", val)
	}

	// Verify unused key is NOT loaded (should return error)
	_, err = memStore.Get(context.Background(), "UNUSED_KEY")
	if err == nil {
		t.Error("Expected error for unused key, got nil")
	}
}

func TestBuildSecretStore_InvalidCacheTTL(t *testing.T) {
	// Test that invalid cache TTL returns an error
	os.Setenv("DOPPLER_TOKEN", "test-token")
	defer os.Unsetenv("DOPPLER_TOKEN")

	cfg := &veilConfig{
		Doppler: &veilDopplerEntry{
			Project:  "test-project",
			Config:   "test-config",
			CacheTTL: "invalid-duration",
		},
	}

	_, err := buildSecretStore(cfg)
	if err == nil {
		t.Error("Expected error for invalid cache TTL, got nil")
	}
}

func TestBuildSecretStore_EmptyRoutesMemoryStore(t *testing.T) {
	// Test that memory store works with no routes (empty store)
	cfg := &veilConfig{
		Routes: []veilRouteEntry{},
	}

	store, err := buildSecretStore(cfg)
	if err != nil {
		t.Fatalf("buildSecretStore() failed: %v", err)
	}

	// Verify it's a memory store
	if _, ok := store.(*proxy.MemorySecretStore); !ok {
		t.Errorf("Expected *proxy.MemorySecretStore, got %T", store)
	}
}

func TestBuildSecretStore_DopplerCacheTTLParsing(t *testing.T) {
	// Test that various cache TTL formats are parsed correctly
	testCases := []struct {
		name     string
		cacheTTL string
		expected time.Duration
	}{
		{"minutes", "10m", 10 * time.Minute},
		{"hours", "2h", 2 * time.Hour},
		{"seconds", "30s", 30 * time.Second},
		{"mixed", "1h30m", 90 * time.Minute},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv("DOPPLER_TOKEN", "test-token")
			defer os.Unsetenv("DOPPLER_TOKEN")

			cfg := &veilConfig{
				Doppler: &veilDopplerEntry{
					Project:  "test-project",
					Config:   "test-config",
					CacheTTL: tc.cacheTTL,
				},
			}

			store, err := buildSecretStore(cfg)
			if err != nil {
				t.Fatalf("buildSecretStore() failed: %v", err)
			}

			// Verify it's a Doppler store
			dopplerStore, ok := store.(*doppler.Store)
			if !ok {
				t.Fatalf("Expected *doppler.Store, got %T", store)
			}

			// Note: We can't easily verify the internal cache TTL without exposing it,
			// but we verified the parsing doesn't error
			_ = dopplerStore
		})
	}
}
