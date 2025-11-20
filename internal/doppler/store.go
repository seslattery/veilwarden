package doppler

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
)

// Options configures the Doppler secret store.
type Options struct {
	Token    string
	BaseURL  string
	Project  string
	Config   string
	CacheTTL time.Duration
	Timeout  time.Duration
	Client   *http.Client
}

// Store fetches secrets from Doppler with caching.
type Store struct {
	client *http.Client
	opts   Options

	mu    sync.Mutex
	cache map[string]cachedSecret
}

type cachedSecret struct {
	value   string
	expires time.Time
}

// NewStore creates a new Doppler secret store.
func NewStore(opts *Options) *Store {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: opts.Timeout}
	} else {
		opts.Client.Timeout = opts.Timeout
	}
	if opts.BaseURL == "" {
		opts.BaseURL = "https://api.doppler.com"
	}
	if opts.CacheTTL == 0 {
		opts.CacheTTL = 5 * time.Minute
	}
	opts.BaseURL = strings.TrimRight(opts.BaseURL, "/")

	return &Store{
		client: opts.Client,
		opts:   *opts,
		cache:  make(map[string]cachedSecret),
	}
}

// Get retrieves a secret from Doppler by ID, using caching when available.
func (d *Store) Get(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", errors.New("secret id required")
	}

	if value, ok := d.getCached(id); ok {
		return value, nil
	}

	value, err := d.fetchSecret(ctx, id)
	if err != nil {
		return "", err
	}
	d.storeCache(id, value)
	return value, nil
}

func (d *Store) getCached(id string) (string, bool) {
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

func (d *Store) storeCache(id, value string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cache[id] = cachedSecret{
		value:   value,
		expires: time.Now().Add(d.opts.CacheTTL),
	}
}

func (d *Store) fetchSecret(ctx context.Context, id string) (string, error) {
	endpoint := fmt.Sprintf("%s/v3/configs/config/secret?project=%s&config=%s&name=%s",
		d.opts.BaseURL,
		url.QueryEscape(d.opts.Project),
		url.QueryEscape(d.opts.Config),
		url.QueryEscape(id),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("doppler request build: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+d.opts.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("doppler request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("doppler read: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("doppler status %d: %s", resp.StatusCode, summarizeBody(body))
	}

	var parsed secretResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("doppler decode: %w", err)
	}

	if !parsed.Success || parsed.Value == nil {
		return "", fmt.Errorf("doppler error: %s", parsed.message())
	}
	// Use computed value (which includes variable references resolved)
	return parsed.Value.Computed, nil
}

type secretResponse struct {
	Success  bool         `json:"success"`
	Name     string       `json:"name"`
	Value    *secretValue `json:"value"`
	Messages []apiError   `json:"messages"`
}

type secretValue struct {
	Raw      string `json:"raw"`
	Computed string `json:"computed"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (r secretResponse) message() string {
	if len(r.Messages) == 0 {
		return "unknown error"
	}
	return r.Messages[0].Message
}

func summarizeBody(body []byte) string {
	const maxLen = 256
	if len(body) <= maxLen {
		return string(body)
	}
	return string(body[:maxLen]) + "..."
}
