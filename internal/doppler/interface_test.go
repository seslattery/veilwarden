package doppler

import (
	"context"
	"github.com/seslattery/veilwarden/internal/proxy"
)

// Compile-time check that Store implements proxy.SecretStore
var _ proxy.SecretStore = (*Store)(nil)

// Example usage showing interface compatibility
func ExampleStore_interface() {
	opts := &Options{
		Token:   "test-token",
		Project: "test-project",
		Config:  "test-config",
	}

	var store proxy.SecretStore = NewStore(opts)

	// Use the store through the interface
	_, _ = store.Get(context.Background(), "test-secret")
}
