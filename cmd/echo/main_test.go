package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStreamEndpoint_ReturnsChunkedData(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", echoHandler)
	mux.HandleFunc("/stream", streamHandler)

	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := http.Get(server.URL + "/stream?duration=2&interval=500")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read chunks and verify sequence
	scanner := bufio.NewScanner(resp.Body)
	var chunks []StreamChunk
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var chunk StreamChunk
		if err := json.Unmarshal([]byte(line), &chunk); err != nil {
			t.Fatalf("failed to parse chunk: %v", err)
		}
		chunks = append(chunks, chunk)
	}

	if len(chunks) < 3 {
		t.Errorf("expected at least 3 chunks, got %d", len(chunks))
	}

	// Last chunk should be marked complete
	if !chunks[len(chunks)-1].Complete {
		t.Error("last chunk should have complete=true")
	}

	// Verify sequence numbers are in order
	for i, chunk := range chunks {
		if chunk.Seq != i {
			t.Errorf("chunk %d has seq %d", i, chunk.Seq)
		}
	}
}

func TestIdleEndpoint_WaitsThenResponds(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/idle", idleHandler)

	server := httptest.NewServer(mux)
	defer server.Close()

	start := time.Now()
	resp, err := http.Get(server.URL + "/idle?delay=2")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)
	if elapsed < 2*time.Second {
		t.Errorf("expected delay of ~2s, got %v", elapsed)
	}

	var result IdleResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !result.Complete {
		t.Error("expected complete=true")
	}
	if result.DelaySeconds != 2 {
		t.Errorf("expected delay_seconds=2, got %d", result.DelaySeconds)
	}
}
