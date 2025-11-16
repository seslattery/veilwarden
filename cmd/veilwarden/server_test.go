package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	}, nil, nil, "", "", "")
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
	server := newProxyServer(map[string]route{}, "good", &configSecretStore{secrets: map[string]string{}}, nil, nil, "", "", "")

	req := httptest.NewRequest(http.MethodGet, "http://veilwarden/foo", nil)
	req.Header.Set(sessionHeader, "bad")
	req.Header.Set(upstreamHeader, "example.com")

	rec := httptest.NewRecorder()
	server.handleHTTP(rec, req)

	assertJSONError(t, rec.Result(), http.StatusUnauthorized, "UNAUTHORIZED")
}

func TestProxyHostValidation(t *testing.T) {
	server := newProxyServer(map[string]route{}, "good", &configSecretStore{secrets: map[string]string{}}, nil, nil, "", "", "")

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
	}, nil, nil, "", "", "")
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

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
