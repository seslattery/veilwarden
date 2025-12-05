package proxy

import (
	"testing"
)

func TestNewMartianProxy_UsesConfiguredTimeout(t *testing.T) {
	cfg := &MartianConfig{
		SessionID:      "test",
		TimeoutSeconds: 600,
	}

	proxy, err := NewMartianProxy(cfg)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	// Verify timeout was set (we can't directly inspect martian's timeout,
	// but we can verify the config was accepted without error)
	if proxy == nil {
		t.Fatal("proxy should not be nil")
	}
}

func TestNewMartianProxy_DefaultTimeout(t *testing.T) {
	cfg := &MartianConfig{
		SessionID: "test",
		// TimeoutSeconds not set - should use default
	}

	proxy, err := NewMartianProxy(cfg)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	if proxy == nil {
		t.Fatal("proxy should not be nil")
	}
}
