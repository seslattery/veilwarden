package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	testing2 "k8s.io/client-go/testing"
)

func TestProxyForwardsRequest(t *testing.T) {
	host := "api.test"
	routes := map[string]route{
		strings.ToLower(host): {
			upstreamHost:        host,
			upstreamScheme:      "http",
			secretID:            "stripe",
			headerName:          "Authorization",
			headerValueTemplate: "Bearer {{secret}}",
		},
	}
	server := newProxyServer(routes, "session", &configSecretStore{
		secrets: map[string]string{"stripe": "sk_test"},
	}, nil, nil, nil, "", "", "")
	server.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Scheme != "http" {
				t.Fatalf("unexpected scheme %s", req.URL.Scheme)
			}
			if req.URL.Host != host {
				t.Fatalf("unexpected host %s", req.URL.Host)
			}
			if req.URL.Path != "/v1/test" {
				t.Fatalf("expected path /v1/test, got %s", req.URL.Path)
			}
			if req.Header.Get("Authorization") != "Bearer sk_test" {
				t.Fatalf("secret header missing")
			}
			if req.Header.Get(sessionHeader) != "" {
				t.Fatalf("session header should be stripped")
			}
			body, _ := io.ReadAll(req.Body)
			if string(body) != "payload" {
				t.Fatalf("unexpected body %q", string(body))
			}
			return &http.Response{
				StatusCode: http.StatusCreated,
				Header:     http.Header{"Upstream": []string{"ok"}},
				Body:       io.NopCloser(strings.NewReader("from-upstream")),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "http://veilwarden/v1/test", strings.NewReader("payload"))
	req.Header.Set(sessionHeader, "session")
	req.Header.Set(upstreamHeader, host)

	rec := httptest.NewRecorder()
	server.handleHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
	if resp.Header.Get(requestIDHeader) == "" {
		t.Fatalf("missing request id header")
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Upstream") != "ok" {
		t.Fatalf("missing upstream header")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "from-upstream" {
		t.Fatalf("unexpected response body %q", string(body))
	}
}

func TestProxyUnauthorized(t *testing.T) {
	server := newProxyServer(map[string]route{}, "good", &configSecretStore{secrets: map[string]string{}}, nil, nil, nil, "", "", "")

	req := httptest.NewRequest(http.MethodGet, "http://veilwarden/foo", nil)
	req.Header.Set(sessionHeader, "bad")
	req.Header.Set(upstreamHeader, "example.com")

	rec := httptest.NewRecorder()
	server.handleHTTP(rec, req)

	assertJSONError(t, rec.Result(), http.StatusUnauthorized, "UNAUTHORIZED")
}

func TestProxyHostValidation(t *testing.T) {
	server := newProxyServer(map[string]route{}, "good", &configSecretStore{secrets: map[string]string{}}, nil, nil, nil, "", "", "")

	req := httptest.NewRequest(http.MethodGet, "http://veilwarden/foo", nil)
	req.Header.Set(sessionHeader, "good")

	rec := httptest.NewRecorder()
	server.handleHTTP(rec, req)
	assertJSONError(t, rec.Result(), http.StatusBadRequest, "MISSING_HOST")

	req = httptest.NewRequest(http.MethodGet, "http://veilwarden/foo", nil)
	req.Header.Set(sessionHeader, "good")
	req.Header.Set(upstreamHeader, "unknown")
	rec = httptest.NewRecorder()
	server.handleHTTP(rec, req)
	assertJSONError(t, rec.Result(), http.StatusForbidden, "HOST_NOT_ALLOWED")
}

func TestProxyClientProvidedRequestID(t *testing.T) {
	host := "api.test"
	routes := map[string]route{
		strings.ToLower(host): {
			upstreamHost:        host,
			upstreamScheme:      "http",
			secretID:            "test",
			headerName:          "Authorization",
			headerValueTemplate: "Bearer {{secret}}",
		},
	}
	server := newProxyServer(routes, "session", &configSecretStore{
		secrets: map[string]string{"test": "secret"},
	}, nil, nil, nil, "", "", "")
	server.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
	}

	clientRequestID := "client-provided-id-12345"
	req := httptest.NewRequest(http.MethodGet, "http://veilwarden/test", nil)
	req.Header.Set(sessionHeader, "session")
	req.Header.Set(upstreamHeader, host)
	req.Header.Set(requestIDHeader, clientRequestID)

	rec := httptest.NewRecorder()
	server.handleHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	// Verify the client-provided request ID is echoed back
	returnedID := resp.Header.Get(requestIDHeader)
	if returnedID != clientRequestID {
		t.Fatalf("expected request id %s, got %s", clientRequestID, returnedID)
	}
}

func assertJSONError(t *testing.T, resp *http.Response, status int, code string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("expected status %d, got %d", status, resp.StatusCode)
	}
	reqID := resp.Header.Get(requestIDHeader)
	if reqID == "" {
		t.Fatalf("missing %s header", requestIDHeader)
	}
	defer resp.Body.Close()
	var payload errorResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if payload.Error != code {
		t.Fatalf("expected error code %s, got %s", code, payload.Error)
	}
	if payload.RequestID != reqID {
		t.Fatalf("expected request id %s, got %s", reqID, payload.RequestID)
	}
}

func TestAuthenticateWithSessionSecret(t *testing.T) {
	server := newProxyServer(map[string]route{}, "test-secret", &configSecretStore{secrets: map[string]string{}}, nil, nil, nil, "alice", "alice@example.com", "engineering")

	req := httptest.NewRequest(http.MethodGet, "http://veilwarden/test", nil)
	req.Header.Set(sessionHeader, "test-secret")

	ident, err := server.authenticate(req)
	if err != nil {
		t.Fatalf("authentication failed: %v", err)
	}

	if ident.Type() != "static" {
		t.Errorf("expected identity type 'static', got %s", ident.Type())
	}

	staticIdent, ok := ident.(*staticIdentity)
	if !ok {
		t.Fatalf("expected staticIdentity, got %T", ident)
	}

	if staticIdent.userID != "alice" {
		t.Errorf("expected userID 'alice', got %s", staticIdent.userID)
	}
	if staticIdent.userEmail != "alice@example.com" {
		t.Errorf("expected userEmail 'alice@example.com', got %s", staticIdent.userEmail)
	}
	if staticIdent.userOrg != "engineering" {
		t.Errorf("expected userOrg 'engineering', got %s", staticIdent.userOrg)
	}
}

func TestAuthenticateMissingCredentials(t *testing.T) {
	server := newProxyServer(map[string]route{}, "test-secret", &configSecretStore{secrets: map[string]string{}}, nil, nil, nil, "", "", "")

	req := httptest.NewRequest(http.MethodGet, "http://veilwarden/test", nil)

	_, err := server.authenticate(req)
	if err == nil {
		t.Fatal("expected authentication to fail with missing credentials")
	}

	if !strings.Contains(err.Error(), "missing authentication") {
		t.Errorf("expected 'missing authentication' error, got: %v", err)
	}
}

func TestAuthenticateInvalidSessionSecret(t *testing.T) {
	server := newProxyServer(map[string]route{}, "correct-secret", &configSecretStore{secrets: map[string]string{}}, nil, nil, nil, "", "", "")

	req := httptest.NewRequest(http.MethodGet, "http://veilwarden/test", nil)
	req.Header.Set(sessionHeader, "wrong-secret")

	_, err := server.authenticate(req)
	if err == nil {
		t.Fatal("expected authentication to fail with invalid secret")
	}

	if !strings.Contains(err.Error(), "invalid session secret") {
		t.Errorf("expected 'invalid session secret' error, got: %v", err)
	}
}

func TestProxyServerAuthenticateK8s(t *testing.T) {
	// Setup fake Kubernetes client
	fakeClient := fake.NewSimpleClientset()
	k8sAuth := &k8sAuthenticator{
		client:  &k8sClient{clientset: fakeClient},
		enabled: true,
	}

	// Setup fake TokenReview response
	fakeClient.PrependReactor("create", "tokenreviews", func(action testing2.Action) (bool, runtime.Object, error) {
		review := &authv1.TokenReview{
			Status: authv1.TokenReviewStatus{
				Authenticated: true,
				User: authv1.UserInfo{
					Username: "system:serviceaccount:default:test-sa",
				},
			},
		}
		return true, review, nil
	})

	proxy := &proxyServer{
		sessionSecret: "test-secret",
		k8sAuth:       k8sAuth,
	}

	// Test Kubernetes authentication
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-k8s-token")

	identity, err := proxy.authenticate(req)
	if err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}

	k8sIdent, ok := identity.(*k8sIdentity)
	if !ok {
		t.Fatalf("expected k8sIdentity, got %T", identity)
	}

	if k8sIdent.namespace != "default" {
		t.Errorf("expected namespace 'default', got %q", k8sIdent.namespace)
	}
	if k8sIdent.serviceAccount != "test-sa" {
		t.Errorf("expected serviceAccount 'test-sa', got %q", k8sIdent.serviceAccount)
	}
}

func TestProxyServerAuthenticateSessionSecret(t *testing.T) {
	proxy := &proxyServer{
		sessionSecret: "test-secret",
		k8sAuth:       &k8sAuthenticator{enabled: false},
		userID:        "alice",
		userEmail:     "alice@example.com",
		userOrg:       "engineering",
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Session-Secret", "test-secret")

	identity, err := proxy.authenticate(req)
	if err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}

	staticIdent, ok := identity.(*staticIdentity)
	if !ok {
		t.Fatalf("expected staticIdentity, got %T", identity)
	}

	if staticIdent.userID != "alice" {
		t.Errorf("expected userID 'alice', got %q", staticIdent.userID)
	}
}

func TestProxyServerAuthenticatePriority(t *testing.T) {
	// Test that K8s token takes priority over session secret

	fakeClient := fake.NewSimpleClientset()
	k8sAuth := &k8sAuthenticator{
		client:  &k8sClient{clientset: fakeClient},
		enabled: true,
	}

	fakeClient.PrependReactor("create", "tokenreviews", func(action testing2.Action) (bool, runtime.Object, error) {
		review := &authv1.TokenReview{
			Status: authv1.TokenReviewStatus{
				Authenticated: true,
				User: authv1.UserInfo{
					Username: "system:serviceaccount:prod:api",
				},
			},
		}
		return true, review, nil
	})

	proxy := &proxyServer{
		sessionSecret: "session-secret",
		k8sAuth:       k8sAuth,
		userID:        "alice",
	}

	// Request with BOTH Bearer token and session secret
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer k8s-token")
	req.Header.Set("X-Session-Secret", "session-secret")

	identity, err := proxy.authenticate(req)
	if err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}

	// Should use K8s identity (higher priority)
	if identity.Type() != "kubernetes" {
		t.Errorf("expected kubernetes identity, got %s", identity.Type())
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
