package doppler

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDopplerSecretStoreFetchAndCache(t *testing.T) {
	var hits int32
	client := &http.Client{
		Transport: dopplerRoundTripper(func(req *http.Request) (*http.Response, error) {
			atomic.AddInt32(&hits, 1)
			if got := req.Header.Get("Authorization"); got != "Bearer token" {
				t.Fatalf("unexpected auth header: %s", got)
			}
			if req.URL.Path != "/v3/configs/config/secret" {
				t.Fatalf("unexpected path %s", req.URL.Path)
			}
			q := req.URL.Query()
			if q.Get("project") != "proj" {
				t.Fatalf("unexpected project query param: %s", q.Get("project"))
			}
			if q.Get("config") != "dev" {
				t.Fatalf("unexpected config query param: %s", q.Get("config"))
			}
			if q.Get("name") != "stripe" {
				t.Fatalf("unexpected name query param: %s", q.Get("name"))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"success":true,"name":"stripe","value":{"raw":"sk_live","computed":"sk_live"}}`)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			}, nil
		}),
	}

	store := NewStore(&Options{
		Token:    "token",
		BaseURL:  "https://doppler.test",
		Project:  "proj",
		Config:   "dev",
		Client:   client,
		CacheTTL: time.Minute,
		Timeout:  2 * time.Second,
	})

	ctx := context.Background()
	val, err := store.Get(ctx, "stripe")
	if err != nil {
		t.Fatalf("get error: %v", err)
	}
	if val != "sk_live" {
		t.Fatalf("unexpected value %q", val)
	}
	val2, err := store.Get(ctx, "stripe")
	if err != nil {
		t.Fatalf("second get error: %v", err)
	}
	if val2 != "sk_live" {
		t.Fatalf("unexpected cached value %q", val2)
	}
	if hits != 1 {
		t.Fatalf("expected one HTTP call, got %d", hits)
	}
}

func TestDopplerSecretStoreHTTPError(t *testing.T) {
	client := &http.Client{
		Transport: dopplerRoundTripper(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(strings.NewReader(`{"success":false,"messages":[{"message":"invalid token"}]}`)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	store := NewStore(&Options{
		Token:   "bad",
		BaseURL: "https://doppler.test",
		Project: "proj",
		Config:  "dev",
		Client:  client,
	})
	if _, err := store.Get(context.Background(), "stripe"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestDopplerSecretStoreAPIFailure(t *testing.T) {
	client := &http.Client{
		Transport: dopplerRoundTripper(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"success":false,"messages":[{"message":"not found"}]}`)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	store := NewStore(&Options{
		Token:   "t",
		BaseURL: "https://doppler.test",
		Project: "proj",
		Config:  "dev",
		Client:  client,
	})
	if _, err := store.Get(context.Background(), "missing"); err == nil {
		t.Fatalf("expected api error")
	}
}

type dopplerRoundTripper func(*http.Request) (*http.Response, error)

func (f dopplerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
