package main

import (
	"context"
	"strings"
	"testing"

	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestK8sAuthenticatorDisabled(t *testing.T) {
	auth, err := newK8sAuthenticator(false)
	if err != nil {
		t.Fatalf("newK8sAuthenticator(false) failed: %v", err)
	}

	_, err = auth.authenticate(context.Background(), "fake-token")
	if err == nil {
		t.Fatal("expected error when authenticator disabled")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Errorf("expected 'disabled' error, got: %v", err)
	}
}

func TestK8sClientValidateToken(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	client := &k8sClient{clientset: fakeClient}

	// Setup fake response
	fakeClient.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := &authv1.TokenReview{
			Status: authv1.TokenReviewStatus{
				Authenticated: true,
				User: authv1.UserInfo{
					Username: "system:serviceaccount:default:test-sa",
					Extra: map[string]authv1.ExtraValue{
						"authentication.kubernetes.io/pod-name": {"test-pod"},
					},
				},
			},
		}
		return true, review, nil
	})

	identity, err := client.validateToken(context.Background(), "valid-token")
	if err != nil {
		t.Fatalf("validateToken failed: %v", err)
	}

	if identity.namespace != "default" {
		t.Errorf("expected namespace 'default', got %q", identity.namespace)
	}
	if identity.serviceAccount != "test-sa" {
		t.Errorf("expected serviceAccount 'test-sa', got %q", identity.serviceAccount)
	}
	if identity.podName != "test-pod" {
		t.Errorf("expected podName 'test-pod', got %q", identity.podName)
	}
}

func TestK8sClientValidateTokenFailed(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	client := &k8sClient{clientset: fakeClient}

	// Setup fake failure response
	fakeClient.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := &authv1.TokenReview{
			Status: authv1.TokenReviewStatus{
				Authenticated: false,
				Error:         "token expired",
			},
		}
		return true, review, nil
	})

	_, err := client.validateToken(context.Background(), "expired-token")
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected 'expired' error, got: %v", err)
	}
}
