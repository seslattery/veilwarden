package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type dopplerOptions struct {
	token    string
	baseURL  string
	project  string
	config   string
	cacheTTL time.Duration
	timeout  time.Duration
	client   *http.Client
}

type dopplerSecretStore struct {
	client *http.Client
	opts   dopplerOptions
	tracer trace.Tracer

	mu    sync.Mutex
	cache map[string]cachedSecret
}

type cachedSecret struct {
	value   string
	expires time.Time
}

func newDopplerSecretStore(opts dopplerOptions) *dopplerSecretStore {
	if opts.timeout <= 0 {
		opts.timeout = 5 * time.Second
	}
	if opts.client == nil {
		opts.client = &http.Client{Timeout: opts.timeout}
	} else {
		opts.client.Timeout = opts.timeout
	}
	if opts.baseURL == "" {
		opts.baseURL = "https://api.doppler.com"
	}
	if opts.cacheTTL == 0 {
		opts.cacheTTL = 5 * time.Minute
	}
	opts.baseURL = strings.TrimRight(opts.baseURL, "/")
	return &dopplerSecretStore{
		client: opts.client,
		opts:   opts,
		tracer: otel.Tracer(serviceName),
		cache:  make(map[string]cachedSecret),
	}
}

func (d *dopplerSecretStore) Get(ctx context.Context, id string) (string, error) {
	ctx, span := d.tracer.Start(ctx, "doppler.get_secret",
		trace.WithAttributes(
			attribute.String("secret.id", id),
		),
	)
	defer span.End()

	if id == "" {
		span.SetStatus(codes.Error, "empty secret id")
		return "", errors.New("secret id required")
	}

	if value, ok := d.getCached(id); ok {
		span.SetAttributes(attribute.Bool("cache.hit", true))
		span.SetStatus(codes.Ok, "cache hit")
		return value, nil
	}

	span.SetAttributes(attribute.Bool("cache.hit", false))
	value, err := d.fetchSecret(ctx, id)
	if err != nil {
		span.SetStatus(codes.Error, "failed to fetch secret")
		return "", err
	}
	d.storeCache(id, value)
	span.SetStatus(codes.Ok, "secret retrieved")
	return value, nil
}

func (d *dopplerSecretStore) getCached(id string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if entry, ok := d.cache[id]; ok {
		if time.Now().Before(entry.expires) {
			return entry.value, true
		}
		delete(d.cache, id)
	}
	return "", false
}

func (d *dopplerSecretStore) storeCache(id, value string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cache[id] = cachedSecret{
		value:   value,
		expires: time.Now().Add(d.opts.cacheTTL),
	}
}

func (d *dopplerSecretStore) fetchSecret(ctx context.Context, id string) (string, error) {
	ctx, span := d.tracer.Start(ctx, "doppler.fetch_secret",
		trace.WithAttributes(
			attribute.String("doppler.project", d.opts.project),
			attribute.String("doppler.config", d.opts.config),
			attribute.String("secret.id", id),
		),
	)
	defer span.End()

	endpoint := fmt.Sprintf("%s/v3/configs/config/secret?project=%s&config=%s&name=%s",
		d.opts.baseURL,
		url.QueryEscape(d.opts.project),
		url.QueryEscape(d.opts.config),
		url.QueryEscape(id),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		span.SetStatus(codes.Error, "failed to build request")
		return "", fmt.Errorf("doppler request build: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+d.opts.token)
	req.Header.Set("Accept", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		span.SetStatus(codes.Error, "http request failed")
		return "", fmt.Errorf("doppler request: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("doppler read: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("doppler status %d: %s", resp.StatusCode, summarizeBody(body))
	}

	var parsed dopplerSecretResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("doppler decode: %w", err)
	}

	if !parsed.Success || parsed.Value == nil {
		span.SetStatus(codes.Error, "doppler api error")
		return "", fmt.Errorf("doppler error: %s", parsed.message())
	}
	// Use computed value (which includes variable references resolved)
	span.SetStatus(codes.Ok, "secret fetched successfully")
	return parsed.Value.Computed, nil
}

type dopplerSecretResponse struct {
	Success  bool              `json:"success"`
	Name     string            `json:"name"`
	Value    *dopplerValue     `json:"value"`
	Messages []dopplerAPIError `json:"messages"`
}

type dopplerValue struct {
	Raw      string `json:"raw"`
	Computed string `json:"computed"`
}

type dopplerAPIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (r dopplerSecretResponse) message() string {
	if len(r.Messages) == 0 {
		return "unknown error"
	}
	return r.Messages[0].Message
}

func summarizeBody(body []byte) string {
	const max = 256
	if len(body) <= max {
		return string(body)
	}
	return string(body[:max]) + "..."
}
