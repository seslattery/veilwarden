package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	defaultAddr := "127.0.0.1:9090"
	if env := os.Getenv("ECHO_ADDR"); env != "" {
		defaultAddr = env
	}
	addr := flag.String("listen", defaultAddr, "address for the echo server")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", echoHandler)
	mux.HandleFunc("/stream", streamHandler)
	mux.HandleFunc("/idle", idleHandler)

	server := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0, // Disable for streaming support
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("echo server listening on http://%s\n", *addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("echo server failed: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("echo server shutdown error: %v", err)
	}
}

type echoResponse struct {
	Method  string      `json:"method"`
	Path    string      `json:"path"`
	Headers http.Header `json:"headers"`
	Body    string      `json:"body"`
}

// StreamChunk represents a single chunk in a streaming response.
type StreamChunk struct {
	Seq      int       `json:"seq"`
	Time     time.Time `json:"time"`
	Msg      string    `json:"msg"`
	Complete bool      `json:"complete,omitempty"`
}

// IdleResponse is returned after an idle delay completes.
type IdleResponse struct {
	DelaySeconds int       `json:"delay_seconds"`
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time"`
	Complete     bool      `json:"complete"`
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusInternalServerError)
		return
	}

	resp := echoResponse{
		Method:  r.Method,
		Path:    r.URL.Path,
		Headers: r.Header.Clone(),
		Body:    string(body),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("echo encode error: %v", err)
	}
}

func streamHandler(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	durationStr := r.URL.Query().Get("duration")
	intervalStr := r.URL.Query().Get("interval")

	duration := 45 * time.Second // default 45 seconds
	if durationStr != "" {
		if d, err := time.ParseDuration(durationStr + "s"); err == nil {
			duration = d
		}
	}

	interval := 500 * time.Millisecond // default 500ms between chunks
	if intervalStr != "" {
		if i, err := time.ParseDuration(intervalStr + "ms"); err == nil {
			interval = i
		}
	}

	// Enable chunked transfer encoding
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	start := time.Now()
	seq := 0

	for time.Since(start) < duration {
		chunk := StreamChunk{
			Seq:  seq,
			Time: time.Now(),
			Msg:  "chunk",
		}

		data, _ := json.Marshal(chunk)
		w.Write(data)
		w.Write([]byte("\n"))
		flusher.Flush()

		seq++
		time.Sleep(interval)
	}

	// Send final chunk with complete marker
	finalChunk := StreamChunk{
		Seq:      seq,
		Time:     time.Now(),
		Msg:      "final",
		Complete: true,
	}
	data, _ := json.Marshal(finalChunk)
	w.Write(data)
	w.Write([]byte("\n"))
	flusher.Flush()
}

func idleHandler(w http.ResponseWriter, r *http.Request) {
	delayStr := r.URL.Query().Get("delay")

	delay := 45 // default 45 seconds
	if delayStr != "" {
		if d, err := strconv.Atoi(delayStr); err == nil && d > 0 {
			delay = d
		}
	}

	start := time.Now()
	time.Sleep(time.Duration(delay) * time.Second)

	resp := IdleResponse{
		DelaySeconds: delay,
		StartTime:    start,
		EndTime:      time.Now(),
		Complete:     true,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
