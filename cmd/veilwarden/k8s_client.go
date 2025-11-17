package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type k8sClient struct {
	clientset kubernetes.Interface
}

// newK8sClient creates a Kubernetes client for TokenReview API calls.
// In-cluster config is attempted first, falling back to kubeconfig for local development.
func newK8sClient() (*k8sClient, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fallback to kubeconfig for local development
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				// Fallback to empty if home dir unavailable
				kubeconfig = ""
			} else {
				kubeconfig = filepath.Join(home, ".kube", "config")
			}
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build kubeconfig: %w", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return &k8sClient{clientset: clientset}, nil
}

// validateToken validates a Service Account token using TokenReview API.
// Returns the authenticated identity on success.
func (c *k8sClient) validateToken(ctx context.Context, token string) (*k8sIdentity, error) {
	review := &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token: token,
		},
	}

	result, err := c.clientset.AuthenticationV1().TokenReviews().Create(
		ctx, review, metav1.CreateOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("tokenreview api call failed: %w", err)
	}

	if !result.Status.Authenticated {
		return nil, fmt.Errorf("token authentication failed: %s", result.Status.Error)
	}

	// Parse username: system:serviceaccount:NAMESPACE:SERVICEACCOUNT
	username := result.Status.User.Username
	namespace, serviceAccount, err := parseServiceAccountUsername(username)
	if err != nil {
		return nil, err
	}

	return &k8sIdentity{
		namespace:      namespace,
		serviceAccount: serviceAccount,
		podName:        extractPodName(result.Status.User.Extra),
		username:       username,
	}, nil
}

// parseServiceAccountUsername parses "system:serviceaccount:NS:SA" format.
func parseServiceAccountUsername(username string) (namespace, serviceAccount string, err error) {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(username, prefix) {
		return "", "", fmt.Errorf("invalid service account username format: %s", username)
	}

	parts := strings.SplitN(username[len(prefix):], ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid service account username: %s", username)
	}

	return parts[0], parts[1], nil
}

// extractPodName attempts to extract pod name from user extra fields.
// Returns empty string if not available (non-critical).
func extractPodName(extra map[string]authv1.ExtraValue) string {
	if podNames, ok := extra["authentication.kubernetes.io/pod-name"]; ok && len(podNames) > 0 {
		return podNames[0]
	}
	return ""
}
