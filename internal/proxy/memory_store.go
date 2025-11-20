package proxy

import (
	"context"
	"fmt"
)

// MemorySecretStore is an in-memory implementation of SecretStore for testing.
type MemorySecretStore struct {
	secrets map[string]string
}

// NewMemorySecretStore creates a new in-memory secret store.
func NewMemorySecretStore(secrets map[string]string) *MemorySecretStore {
	return &MemorySecretStore{
		secrets: secrets,
	}
}

// Get retrieves a secret from the in-memory store.
func (s *MemorySecretStore) Get(ctx context.Context, secretID string) (string, error) {
	secret, ok := s.secrets[secretID]
	if !ok {
		return "", fmt.Errorf("secret %s not found", secretID)
	}
	return secret, nil
}
