//go:build e2e
// +build e2e

package main

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// TestE2EKubernetesWorkloadIdentity tests full Kubernetes integration.
// Prerequisites:
//   - kind cluster running
//   - KUBECONFIG set to kind cluster
//   - veilwarden proxy running (deployed or local)
func TestE2EKubernetesWorkloadIdentity(t *testing.T) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("KUBECONFIG not set, skipping e2e test")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("failed to build config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("failed to create clientset: %v", err)
	}

	ctx := context.Background()

	// Create test namespace
	namespace := "veilwarden-e2e"
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}
	_, err = clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		t.Logf("namespace may already exist: %v", err)
	}
	defer func() {
		clientset.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{})
	}()

	// Create ServiceAccount
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-workload",
			Namespace: namespace,
		},
	}
	_, err = clientset.CoreV1().ServiceAccounts(namespace).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create service account: %v", err)
	}

	// Create ClusterRole for TokenReview
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "veilwarden-tokenreview",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
		},
	}
	_, err = clientset.RbacV1().ClusterRoles().Create(ctx, clusterRole, metav1.CreateOptions{})
	if err != nil {
		t.Logf("clusterrole may already exist: %v", err)
	}

	// Create ClusterRoleBinding
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "veilwarden-tokenreview-binding",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "veilwarden-tokenreview",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "veilwarden",
				Namespace: namespace,
			},
		},
	}
	_, err = clientset.RbacV1().ClusterRoleBindings().Create(ctx, binding, metav1.CreateOptions{})
	if err != nil {
		t.Logf("binding may already exist: %v", err)
	}

	// Wait for token to be created
	t.Log("Waiting for ServiceAccount token to be created...")
	time.Sleep(3 * time.Second)

	// Get ServiceAccount token
	sa, err = clientset.CoreV1().ServiceAccounts(namespace).Get(ctx, "test-workload", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get service account: %v", err)
	}

	if len(sa.Secrets) == 0 {
		t.Fatal("service account has no secrets")
	}

	secret, err := clientset.CoreV1().Secrets(namespace).Get(ctx, sa.Secrets[0].Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	token := string(secret.Data["token"])
	if token == "" {
		t.Fatal("token is empty")
	}

	t.Logf("Successfully retrieved ServiceAccount token")

	// Start veilwarden proxy (assumes it's been deployed or we start it locally pointing at cluster)
	// For simplicity, this test assumes proxy is already running
	proxyURL := os.Getenv("VEILWARDEN_URL")
	if proxyURL == "" {
		proxyURL = "http://localhost:8088"
	}

	t.Logf("Testing against veilwarden proxy at: %s", proxyURL)

	// Make request with Kubernetes token
	req, err := http.NewRequest("GET", proxyURL+"/healthz", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Upstream-Host", "httpbin.org")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	t.Log("E2E test with Kubernetes workload identity passed")
}

// TestE2EKubernetesInvalidToken tests that invalid tokens are rejected.
func TestE2EKubernetesInvalidToken(t *testing.T) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("KUBECONFIG not set, skipping e2e test")
	}

	proxyURL := os.Getenv("VEILWARDEN_URL")
	if proxyURL == "" {
		proxyURL = "http://localhost:8088"
	}

	// Make request with invalid token
	req, err := http.NewRequest("GET", proxyURL+"/test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer invalid-token-12345")
	req.Header.Set("X-Upstream-Host", "httpbin.org")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Error("expected non-200 status for invalid token, got 200")
	}

	t.Logf("Invalid token correctly rejected with status: %d", resp.StatusCode)
}
