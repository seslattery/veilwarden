//go:build integration
// +build integration

package main

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestK8sAuthenticationIntegration(t *testing.T) {
	// Start EnvTest (real API server)
	testEnv := &envtest.Environment{
		CRDDirectoryPaths: []string{},
	}

	cfg, err := testEnv.Start()
	if err != nil {
		t.Fatalf("failed to start test environment: %v", err)
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

	// Wait for token to be created
	time.Sleep(2 * time.Second)

	// Get ServiceAccount token
	sa, err = clientset.CoreV1().ServiceAccounts("test-integration").Get(context.Background(), "test-sa", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get service account: %v", err)
	}

	if len(sa.Secrets) == 0 {
		t.Fatal("service account has no secrets")
	}

	secret, err := clientset.CoreV1().Secrets("test-integration").Get(context.Background(), sa.Secrets[0].Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	token := string(secret.Data["token"])
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
		t.Fatalf("failed to start test environment: %v", err)
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
