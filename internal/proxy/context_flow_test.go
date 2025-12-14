package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPolicyBlockContextPreservation tests that the policy blocked context
// set by policyModifier is preserved and accessible by policyEnforcingRoundTripper.
func TestPolicyBlockContextPreservation(t *testing.T) {
	// Create a mock policy engine that denies all requests
	mockEngine := &mockDenyAllEngine{}

	// Create the policy modifier with a logger
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	modifier := &policyModifier{
		policyEngine: mockEngine,
		sessionID:    "test-session",
		logger:       logger,
	}

	// Create a test request
	req := httptest.NewRequest("GET", "https://example.com/blocked", nil)
	originalCtx := req.Context()

	// Run the modifier - it should set the blocked context
	err := modifier.ModifyRequest(req)
	require.NoError(t, err, "modifier should not return error, it stores block in context")

	// Verify the context was updated
	newCtx := req.Context()
	assert.NotEqual(t, originalCtx, newCtx, "context should be updated")

	// Verify we can retrieve the blocked error from the request context
	blocked, ok := req.Context().Value(policyBlockedKey).(*policyBlockedError)
	assert.True(t, ok, "should find blocked error in context")
	assert.NotNil(t, blocked, "blocked error should not be nil")
	assert.Equal(t, "denied by test policy", blocked.reason)

	t.Logf("Context preserved correctly - blocked reason: %s", blocked.reason)
}

// TestRoundTripperSeesBlockedContext verifies the RoundTripper can see
// the blocked context set by the modifier and returns a 403 response.
func TestRoundTripperSeesBlockedContext(t *testing.T) {
	// Track if wrapped RoundTripper was called
	wrapperCalled := false
	wrappedRT := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		wrapperCalled = true
		return &http.Response{StatusCode: 200}, nil
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rt := &policyEnforcingRoundTripper{
		wrapped: wrappedRT,
		logger:  logger,
	}

	// Create a request with blocked context already set (as modifier would do)
	req := httptest.NewRequest("GET", "https://example.com/blocked", nil)
	blocked := &policyBlockedError{reason: "test block reason"}
	req = req.WithContext(context.WithValue(req.Context(), policyBlockedKey, blocked))

	// Call RoundTrip - should return a 403 response without calling wrapped
	resp, err := rt.RoundTrip(req)

	assert.NoError(t, err, "should not return error - returns 403 response instead")
	assert.NotNil(t, resp, "should return a 403 response for blocked request")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "should return 403 Forbidden")
	assert.False(t, wrapperCalled, "should NOT call wrapped RoundTripper when blocked")

	// Verify response headers
	assert.Equal(t, "policy", resp.Header.Get("X-Veilwarden-Blocked"))
	assert.Equal(t, "test block reason", resp.Header.Get("X-Veilwarden-Reason"))

	// Verify response body contains the reason
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "test block reason")
}

// TestRoundTripperAllowsUnblockedContext verifies the RoundTripper allows
// requests without blocked context.
func TestRoundTripperAllowsUnblockedContext(t *testing.T) {
	// Track if wrapped RoundTripper was called
	wrapperCalled := false
	wrappedRT := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		wrapperCalled = true
		return &http.Response{StatusCode: 200}, nil
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rt := &policyEnforcingRoundTripper{
		wrapped: wrappedRT,
		logger:  logger,
	}

	// Create a normal request without blocked context
	req := httptest.NewRequest("GET", "https://example.com/allowed", nil)

	// Call RoundTrip - should pass through to wrapped
	resp, err := rt.RoundTrip(req)

	assert.NoError(t, err, "should not return error for allowed request")
	assert.NotNil(t, resp, "should return response for allowed request")
	assert.True(t, wrapperCalled, "should call wrapped RoundTripper when allowed")
}

// Helper types

type mockDenyAllEngine struct{}

func (m *mockDenyAllEngine) Decide(ctx context.Context, input *PolicyInput) (PolicyDecision, error) {
	return PolicyDecision{
		Allowed: false,
		Reason:  "denied by test policy",
	}, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
