package main

import (
	"context"
	"fmt"
)

// k8sAuthenticator handles Kubernetes Service Account token authentication.
type k8sAuthenticator struct {
	client  *k8sClient
	enabled bool
}

// newK8sAuthenticator creates a new Kubernetes authenticator.
// If enabled=true, requires Kubernetes API access (fails if unavailable).
// If enabled=false, returns disabled authenticator (always returns nil).
func newK8sAuthenticator(enabled bool) (*k8sAuthenticator, error) {
	if !enabled {
		return &k8sAuthenticator{enabled: false}, nil
	}

	client, err := newK8sClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return &k8sAuthenticator{
		client:  client,
		enabled: true,
	}, nil
}

// authenticate validates a Kubernetes Service Account token.
// Returns nil if token is invalid or authenticator is disabled.
func (a *k8sAuthenticator) authenticate(ctx context.Context, token string) (*k8sIdentity, error) {
	if !a.enabled {
		return nil, fmt.Errorf("kubernetes authentication disabled")
	}

	return a.client.validateToken(ctx, token)
}
