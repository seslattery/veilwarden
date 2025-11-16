package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandlerOK(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	healthHandler(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	if string(body) != `{"status":"ok"}` {
		t.Fatalf("unexpected body: %s", string(body))
	}

	if got := res.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("unexpected content-type: %s", got)
	}
}

func TestHealthHandlerRejectsNonGET(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	rec := httptest.NewRecorder()

	healthHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", rec.Code)
	}
}

func TestMissingConfigSecrets(t *testing.T) {
	cfg := &appConfig{
		routes: map[string]route{
			"a": {secretID: "one"},
			"b": {secretID: "two"},
		},
		secrets: map[string]string{
			"one": "value",
		},
	}
	missing := missingConfigSecrets(cfg)
	if len(missing) != 1 || missing[0] != "two" {
		t.Fatalf("expected missing secret 'two', got %v", missing)
	}
}

func TestBuildSecretStoreRequiresProjectConfig(t *testing.T) {
	_, err := buildSecretStore(runConfig{
		dopplerToken: "token",
	}, &appConfig{})
	if err == nil {
		t.Fatalf("expected error when doppler project/config not set")
	}
}

func TestBuildSecretStoreMissingConfigValues(t *testing.T) {
	_, err := buildSecretStore(runConfig{}, &appConfig{
		routes: map[string]route{
			"api": {secretID: "missing"},
		},
		secrets: map[string]string{},
	})
	if err == nil {
		t.Fatalf("expected error for missing secret values")
	}
}
