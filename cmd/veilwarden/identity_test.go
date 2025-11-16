package main

import (
	"net/http/httptest"
	"testing"
)

func TestStaticIdentityType(t *testing.T) {
	ident := &staticIdentity{
		userID:    "user123",
		userEmail: "user@example.com",
		userOrg:   "engineering",
	}

	if ident.Type() != "static" {
		t.Errorf("expected type 'static', got %q", ident.Type())
	}
}

func TestStaticIdentityAttributes(t *testing.T) {
	ident := &staticIdentity{
		userID:    "alice",
		userEmail: "alice@example.com",
		userOrg:   "product",
	}

	attrs := ident.Attributes()

	tests := []struct {
		key      string
		expected string
	}{
		{"user_id", "alice"},
		{"user_email", "alice@example.com"},
		{"user_org", "product"},
	}

	for _, tt := range tests {
		if attrs[tt.key] != tt.expected {
			t.Errorf("expected %s=%q, got %q", tt.key, tt.expected, attrs[tt.key])
		}
	}
}

func TestStaticIdentityPolicyInput(t *testing.T) {
	ident := &staticIdentity{
		userID:    "bob",
		userEmail: "bob@example.com",
		userOrg:   "sales",
	}

	input := ident.PolicyInput()

	if input["user_id"] != "bob" {
		t.Errorf("expected user_id 'bob', got %v", input["user_id"])
	}
	if input["user_email"] != "bob@example.com" {
		t.Errorf("expected user_email 'bob@example.com', got %v", input["user_email"])
	}
	if input["user_org"] != "sales" {
		t.Errorf("expected user_org 'sales', got %v", input["user_org"])
	}
}

func TestBuildPolicyInput(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/users?filter=active", nil)
	req.Header.Set("X-Agent-Id", "test-agent")
	req.Header.Set("X-Request-Id", "custom-request-id")

	ident := &staticIdentity{
		userID:    "test-user",
		userEmail: "test@example.com",
		userOrg:   "testing",
	}

	input := buildPolicyInput(req, "api.example.com", ident)

	// Check request fields
	if input["method"] != "POST" {
		t.Errorf("expected method 'POST', got %v", input["method"])
	}
	if input["path"] != "/api/v1/users" {
		t.Errorf("expected path '/api/v1/users', got %v", input["path"])
	}
	if input["query"] != "filter=active" {
		t.Errorf("expected query 'filter=active', got %v", input["query"])
	}
	if input["upstream_host"] != "api.example.com" {
		t.Errorf("expected upstream_host 'api.example.com', got %v", input["upstream_host"])
	}
	if input["agent_id"] != "test-agent" {
		t.Errorf("expected agent_id 'test-agent', got %v", input["agent_id"])
	}
	if input["request_id"] != "custom-request-id" {
		t.Errorf("expected request_id 'custom-request-id', got %v", input["request_id"])
	}

	// Check identity fields merged in
	if input["user_id"] != "test-user" {
		t.Errorf("expected user_id 'test-user', got %v", input["user_id"])
	}
	if input["user_email"] != "test@example.com" {
		t.Errorf("expected user_email 'test@example.com', got %v", input["user_email"])
	}
	if input["user_org"] != "testing" {
		t.Errorf("expected user_org 'testing', got %v", input["user_org"])
	}

	// Check timestamp is present
	if _, ok := input["timestamp"]; !ok {
		t.Error("expected timestamp to be present")
	}
}

func TestBuildPolicyInputGeneratesRequestID(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	// Don't set X-Request-Id header

	ident := &staticIdentity{
		userID:    "user",
		userEmail: "user@example.com",
		userOrg:   "org",
	}

	input := buildPolicyInput(req, "api.test", ident)

	requestID, ok := input["request_id"].(string)
	if !ok {
		t.Fatal("request_id should be a string")
	}
	if requestID == "" {
		t.Error("request_id should be generated when not provided")
	}
	// Should be 32 hex characters (16 bytes)
	if len(requestID) != 32 {
		t.Errorf("expected request_id length 32, got %d", len(requestID))
	}
}

func TestGenerateRequestID(t *testing.T) {
	id1 := generateRequestID()
	id2 := generateRequestID()

	if id1 == "" {
		t.Error("generateRequestID should return non-empty string")
	}
	if id2 == "" {
		t.Error("generateRequestID should return non-empty string")
	}
	if id1 == id2 {
		t.Error("generateRequestID should return unique IDs")
	}
	// Should be 32 hex characters (16 bytes)
	if len(id1) != 32 {
		t.Errorf("expected ID length 32, got %d", len(id1))
	}
}
