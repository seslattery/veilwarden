package main

import (
	"testing"
)

func TestK8sIdentityType(t *testing.T) {
	identity := &k8sIdentity{
		namespace:      "production",
		serviceAccount: "api-server",
		podName:        "api-server-7d9f8",
	}

	if identity.Type() != "kubernetes" {
		t.Errorf("expected type 'kubernetes', got %q", identity.Type())
	}
}

func TestK8sIdentityAttributes(t *testing.T) {
	identity := &k8sIdentity{
		namespace:      "production",
		serviceAccount: "api-server",
		podName:        "api-server-7d9f8",
		username:       "system:serviceaccount:production:api-server",
	}

	attrs := identity.Attributes()

	tests := []struct {
		key      string
		expected string
	}{
		{"namespace", "production"},
		{"service_account", "api-server"},
		{"pod_name", "api-server-7d9f8"},
		{"username", "system:serviceaccount:production:api-server"},
	}

	for _, tt := range tests {
		if attrs[tt.key] != tt.expected {
			t.Errorf("expected %s=%q, got %q", tt.key, tt.expected, attrs[tt.key])
		}
	}
}

func TestK8sIdentityPolicyInput(t *testing.T) {
	identity := &k8sIdentity{
		namespace:      "staging",
		serviceAccount: "worker",
		podName:        "worker-abc123",
		username:       "system:serviceaccount:staging:worker",
	}

	input := identity.PolicyInput()

	if input["namespace"] != "staging" {
		t.Errorf("expected namespace 'staging', got %v", input["namespace"])
	}
	if input["service_account"] != "worker" {
		t.Errorf("expected service_account 'worker', got %v", input["service_account"])
	}
	if input["pod_name"] != "worker-abc123" {
		t.Errorf("expected pod_name 'worker-abc123', got %v", input["pod_name"])
	}
	if input["username"] != "system:serviceaccount:staging:worker" {
		t.Errorf("expected username 'system:serviceaccount:staging:worker', got %v", input["username"])
	}
}

func TestK8sIdentityPolicyInputWithoutPodName(t *testing.T) {
	identity := &k8sIdentity{
		namespace:      "default",
		serviceAccount: "default",
		podName:        "", // Not available
		username:       "system:serviceaccount:default:default",
	}

	input := identity.PolicyInput()

	if _, exists := input["pod_name"]; exists {
		t.Error("pod_name should not be in policy input when empty")
	}

	// Verify other fields are still present
	if input["namespace"] != "default" {
		t.Errorf("expected namespace 'default', got %v", input["namespace"])
	}
	if input["service_account"] != "default" {
		t.Errorf("expected service_account 'default', got %v", input["service_account"])
	}
	if input["username"] != "system:serviceaccount:default:default" {
		t.Errorf("expected username 'system:serviceaccount:default:default', got %v", input["username"])
	}
}
