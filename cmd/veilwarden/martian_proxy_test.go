package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMartianProxyServer_BasicMITM(t *testing.T) {
	// Generate ephemeral CA for test
	sessionID := "test-session"

	// Mock upstream server
	requestReceived := false
	mockUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestReceived = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockUpstream.Close()

	// Create proxy config
	cfg := &MartianProxyConfig{
		SessionID:   sessionID,
		RequireAuth: false,
	}

	proxy, err := NewMartianProxyServer(cfg)
	require.NoError(t, err)

	// Start proxy on random port
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer proxyListener.Close()

	proxyURL := "http://" + proxyListener.Addr().String()

	go proxy.Serve(proxyListener)

	// Create HTTP client configured to use proxy
	proxyURLParsed, _ := url.Parse(proxyURL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURLParsed),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // For testing only
			},
		},
	}

	// Make request through proxy
	resp, err := client.Get(mockUpstream.URL + "/test")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, requestReceived, "request should reach upstream server")
}
