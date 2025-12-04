package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsValidHeaderValue tests the header validation function.
func TestIsValidHeaderValue(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{
			name:     "valid bearer token",
			value:    "Bearer sk-proj-1234567890abcdef",
			expected: true,
		},
		{
			name:     "valid basic auth",
			value:    "Basic dXNlcjpwYXNzd29yZA==",
			expected: true,
		},
		{
			name:     "value with spaces",
			value:    "Bearer token with spaces",
			expected: true,
		},
		{
			name:     "value with tab",
			value:    "Bearer\ttoken",
			expected: true,
		},
		{
			name:     "newline injection - LF",
			value:    "Bearer token\nX-Injected: malicious",
			expected: false,
		},
		{
			name:     "newline injection - CR",
			value:    "Bearer token\rX-Injected: malicious",
			expected: false,
		},
		{
			name:     "newline injection - CRLF",
			value:    "Bearer token\r\nX-Injected: malicious",
			expected: false,
		},
		{
			name:     "null byte injection",
			value:    "Bearer token\x00malicious",
			expected: false,
		},
		{
			name:     "control character",
			value:    "Bearer\x01token",
			expected: false,
		},
		{
			name:     "high ASCII character",
			value:    "Bearer token™",
			expected: false,
		},
		{
			name:     "empty string",
			value:    "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidHeaderValue(tt.value)
			assert.Equal(t, tt.expected, result,
				"isValidHeaderValue(%q) = %v, want %v", tt.value, result, tt.expected)
		})
	}
}

func TestIsValidHeaderValue_Injection(t *testing.T) {
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{"normal", "Bearer sk-1234", true},
		{"with tab", "Bearer\tsk-1234", true},
		{"CRLF injection", "Bearer token\r\nX-Injected: bad", false},
		{"LF only", "Bearer token\nX-Injected: bad", false},
		{"CR only", "Bearer token\rX-Injected: bad", false},
		{"null byte", "Bearer\x00token", false},
		{"high unicode", "Bearer \u0080token", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidHeaderValue(tt.value)
			assert.Equal(t, tt.valid, got)
		})
	}
}

// TestPolicyModifier_LargeBodyDoS tests that large request bodies are limited.
func TestPolicyModifier_LargeBodyDoS(t *testing.T) {
	// Create a mock policy engine that always allows
	policyEngine := &mockPolicyEngine{allowAll: true}

	modifier := &policyModifier{
		policyEngine: policyEngine,
		sessionID:    "test-session",
		logger:       slog.Default(),
	}

	// Create a request with a body larger than MaxPolicyBodySize
	largeBody := strings.Repeat("A", MaxPolicyBodySize+1000)
	req := httptest.NewRequest("POST", "https://api.example.com/test", strings.NewReader(largeBody))

	err := modifier.ModifyRequest(req)
	require.NoError(t, err)

	// Verify the body was truncated for policy evaluation
	// The policyInput.Body should have been truncated
	assert.NotNil(t, policyEngine.lastInput)
	assert.Equal(t, MaxPolicyBodySize, len(policyEngine.lastInput.Body),
		"body should be truncated to MaxPolicyBodySize")

	// Verify the request body is still readable (restored)
	bodyBytes, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, MaxPolicyBodySize, len(bodyBytes),
		"restored body should be truncated version")
}

// TestPolicyModifier_NormalBody tests that normal-sized bodies pass through.
func TestPolicyModifier_NormalBody(t *testing.T) {
	policyEngine := &mockPolicyEngine{allowAll: true}

	modifier := &policyModifier{
		policyEngine: policyEngine,
		sessionID:    "test-session",
		logger:       slog.Default(),
	}

	// Create a request with a normal-sized body
	body := `{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}`
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", strings.NewReader(body))

	err := modifier.ModifyRequest(req)
	require.NoError(t, err)

	// Verify the full body was passed to policy
	assert.Equal(t, body, policyEngine.lastInput.Body)

	// Verify the request body is still readable
	bodyBytes, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, body, string(bodyBytes))
}

// TestSecretInjectorModifier_HeaderInjection tests prevention of header injection.
func TestSecretInjectorModifier_HeaderInjection(t *testing.T) {
	tests := []struct {
		name        string
		secret      string
		template    string
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "valid secret",
			secret:      "sk-proj-valid-secret-12345",
			template:    "Bearer {{secret}}",
			shouldError: false,
		},
		{
			name:        "secret with newline",
			secret:      "sk-secret\nX-Injected: malicious",
			template:    "Bearer {{secret}}",
			shouldError: true,
			errorMsg:    "contains invalid characters for HTTP header",
		},
		{
			name:        "secret with CRLF",
			secret:      "sk-secret\r\nX-Injected: malicious",
			template:    "Bearer {{secret}}",
			shouldError: true,
			errorMsg:    "contains invalid characters for HTTP header",
		},
		{
			name:        "secret with null byte",
			secret:      "sk-secret\x00malicious",
			template:    "Bearer {{secret}}",
			shouldError: true,
			errorMsg:    "contains invalid characters for HTTP header",
		},
		{
			name:        "template with invalid characters",
			secret:      "valid-secret",
			template:    "Bearer {{secret}}\r\nX-Evil: injected",
			shouldError: true,
			errorMsg:    "header value for Authorization contains invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock secret store
			secretStore := &mockSecretStore{
				secrets: map[string]string{
					"TEST_SECRET": tt.secret,
				},
			}

			// Create routes
			routes := map[string]Route{
				"api.example.com": {
					SecretID:            "TEST_SECRET",
					HeaderName:          "Authorization",
					HeaderValueTemplate: tt.template,
				},
			}

			modifier := &secretInjectorModifier{
				routes:      routes,
				secretStore: secretStore,
				logger:      slog.Default(),
			}

			req := httptest.NewRequest("POST", "https://api.example.com/test", nil)

			err := modifier.ModifyRequest(req)

			if tt.shouldError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				// Header should not be set on error
			} else {
				assert.NoError(t, err)
				// Verify header was set correctly
				expectedValue := strings.ReplaceAll(tt.template, "{{secret}}", tt.secret)
				assert.Equal(t, expectedValue, req.Header.Get("Authorization"))
			}
		})
	}
}

// TestSecretInjectorModifier_ValidSecret tests normal secret injection.
func TestSecretInjectorModifier_ValidSecret(t *testing.T) {
	secretStore := &mockSecretStore{
		secrets: map[string]string{
			"OPENAI_KEY": "sk-proj-abc123",
		},
	}

	routes := map[string]Route{
		"api.openai.com": {
			SecretID:            "OPENAI_KEY",
			HeaderName:          "Authorization",
			HeaderValueTemplate: "Bearer {{secret}}",
		},
	}

	modifier := &secretInjectorModifier{
		routes:      routes,
		secretStore: secretStore,
		logger:      slog.Default(),
	}

	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", nil)

	err := modifier.ModifyRequest(req)
	require.NoError(t, err)

	assert.Equal(t, "Bearer sk-proj-abc123", req.Header.Get("Authorization"))
}

// Mock implementations for testing

type mockPolicyEngine struct {
	allowAll  bool
	lastInput *PolicyInput
}

func (m *mockPolicyEngine) Decide(ctx context.Context, input *PolicyInput) (PolicyDecision, error) {
	m.lastInput = input
	return PolicyDecision{
		Allowed: m.allowAll,
		Reason:  "test",
	}, nil
}

type mockSecretStore struct {
	secrets map[string]string
}

func (m *mockSecretStore) Get(ctx context.Context, id string) (string, error) {
	secret, ok := m.secrets[id]
	if !ok {
		return "", fmt.Errorf("secret not found: %s", id)
	}
	return secret, nil
}

// TestPolicyModifier_EmptyBody tests handling of requests with no body.
func TestPolicyModifier_EmptyBody(t *testing.T) {
	policyEngine := &mockPolicyEngine{allowAll: true}

	modifier := &policyModifier{
		policyEngine: policyEngine,
		sessionID:    "test-session",
		logger:       slog.Default(),
	}

	req := httptest.NewRequest("GET", "https://api.example.com/test", nil)

	err := modifier.ModifyRequest(req)
	require.NoError(t, err)

	assert.Empty(t, policyEngine.lastInput.Body)
}

// TestPolicyModifier_BodyRestoration tests that body is properly restored.
func TestPolicyModifier_BodyRestoration(t *testing.T) {
	policyEngine := &mockPolicyEngine{allowAll: true}

	modifier := &policyModifier{
		policyEngine: policyEngine,
		sessionID:    "test-session",
		logger:       slog.Default(),
	}

	originalBody := `{"test": "data"}`
	req := httptest.NewRequest("POST", "https://api.example.com/test",
		bytes.NewReader([]byte(originalBody)))

	err := modifier.ModifyRequest(req)
	require.NoError(t, err)

	// First read
	body1, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, originalBody, string(body1))

	// Body should be consumable (though only once since we don't re-restore)
	req.Body.Close()
}
