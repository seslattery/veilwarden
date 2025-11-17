//go:build integration
// +build integration

package main

import (
	"context"
	"testing"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// ptr is a helper function to get a pointer to a value
func ptr[T any](v T) *T {
	return &v
}

func TestK8sAuthenticationIntegration(t *testing.T) {
	// Start EnvTest (real API server)
	// Requires: setup-envtest to be installed and binaries available
	// Install with: go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
	testEnv := &envtest.Environment{
		CRDDirectoryPaths: []string{},
	}

	cfg, err := testEnv.Start()
	if err != nil {
		t.Skipf("EnvTest binaries not available (install with 'just install-envtest'): %v", err)
		return
	}
	defer testEnv.Stop()

	// Create Kubernetes client
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create clientset: %v", err)
	}

	// Create test namespace
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-integration",
		},
	}
	_, err = clientset.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create namespace: %v", err)
	}

	// Create test ServiceAccount
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sa",
			Namespace: "test-integration",
		},
	}
	_, err = clientset.CoreV1().ServiceAccounts("test-integration").Create(context.Background(), sa, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create service account: %v", err)
	}

	// Create a token for the service account using TokenRequest API (K8s 1.24+)
	// This is the modern way to get service account tokens
	tokenRequest := &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			ExpirationSeconds: ptr(int64(3600)), // 1 hour
		},
	}
	tokenResponse, err := clientset.CoreV1().ServiceAccounts("test-integration").CreateToken(
		context.Background(),
		"test-sa",
		tokenRequest,
		metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	token := tokenResponse.Status.Token
	if token == "" {
		t.Fatal("token is empty")
	}

	// Test token validation
	client := &k8sClient{clientset: clientset}
	identity, err := client.validateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("validateToken failed: %v", err)
	}

	if identity.namespace != "test-integration" {
		t.Errorf("expected namespace 'test-integration', got %q", identity.namespace)
	}
	if identity.serviceAccount != "test-sa" {
		t.Errorf("expected serviceAccount 'test-sa', got %q", identity.serviceAccount)
	}
}

func TestK8sAuthenticationIntegrationInvalidToken(t *testing.T) {
	testEnv := &envtest.Environment{}
	cfg, err := testEnv.Start()
	if err != nil {
		t.Skipf("EnvTest binaries not available (install with 'just install-envtest'): %v", err)
		return
	}
	defer testEnv.Stop()

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create clientset: %v", err)
	}

	client := &k8sClient{clientset: clientset}

	// Test with invalid token
	_, err = client.validateToken(context.Background(), "invalid-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}
