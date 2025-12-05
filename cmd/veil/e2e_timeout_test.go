package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// startTimeoutEchoServer starts the echo server with streaming endpoints
func startTimeoutEchoServer(t *testing.T) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	repoRoot := findRepoRoot(t)
	echoCmd := exec.Command("go", "run", "./cmd/echo", "-listen", addr)
	echoCmd.Dir = repoRoot
	if err := echoCmd.Start(); err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	return addr, func() {
		echoCmd.Process.Kill()
		echoCmd.Wait()
	}
}

// TestStreamingTimeout_CurrentBehavior documents that 30s timeout breaks long streams.
func TestStreamingTimeout_CurrentBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e timeout test in short mode")
	}

	dopplerToken := os.Getenv("DOPPLER_TOKEN")
	if dopplerToken == "" {
		t.Skip("DOPPLER_TOKEN not set")
	}

	backends := detectAvailableBackends()
	if len(backends) == 0 {
		t.Skip("no sandbox backends available")
	}

	ctx := context.Background()
	tmpDir := t.TempDir()

	veilBin := filepath.Join(tmpDir, "veil")
	repoRoot := findRepoRoot(t)
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", veilBin, "./cmd/veil")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build veil: %v\n%s", err, out)
	}

	echoAddr, stopEcho := startTimeoutEchoServer(t)
	defer stopEcho()

	projectDir := filepath.Join(tmpDir, "project")
	os.MkdirAll(projectDir, 0755)

	// Config with SHORT 30s timeout to prove the issue
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(`routes: []
doppler:
  project: veilwarden
  config: dev
proxy:
  timeout_seconds: 30
sandbox:
  enabled: true
  backend: %s
  working_dir: %s
`, backends[0], projectDir)
	os.WriteFile(configPath, []byte(configContent), 0644)

	testScript := fmt.Sprintf(`#!/usr/bin/env python3
import urllib.request, json
url = "http://%s/stream?duration=45&interval=1000"
try:
    with urllib.request.urlopen(url, timeout=120) as resp:
        chunks = []
        for line in resp:
            line = line.decode().strip()
            if line:
                chunks.append(json.loads(line))
        if chunks and chunks[-1].get('complete'):
            print(json.dumps({"status": "complete", "chunks": len(chunks)}))
        else:
            print(json.dumps({"status": "incomplete", "chunks": len(chunks)}))
except Exception as e:
    print(json.dumps({"status": "error", "error": str(e)[:200]}))
`, echoAddr)

	scriptPath := filepath.Join(projectDir, "stream_test.py")
	os.WriteFile(scriptPath, []byte(testScript), 0755)

	timeoutCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, veilBin, "exec", "--config", configPath, "--",
		"python3", scriptPath)
	cmd.Env = append(os.Environ(), "DOPPLER_TOKEN="+dopplerToken)
	output, _ := cmd.CombinedOutput()

	result := extractJSON(string(output))
	var status struct {
		Status string `json:"status"`
	}
	json.Unmarshal([]byte(result), &status)

	t.Logf("Stream test result: %s", result)

	// With 30s timeout, 45s stream should fail
	if status.Status == "complete" {
		t.Error("Expected stream to fail with 30s timeout, but it completed")
	}
}

// TestStreamingTimeout_WithExtendedTimeout verifies streams complete with longer timeout.
func TestStreamingTimeout_WithExtendedTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e timeout test in short mode")
	}

	dopplerToken := os.Getenv("DOPPLER_TOKEN")
	if dopplerToken == "" {
		t.Skip("DOPPLER_TOKEN not set")
	}

	backends := detectAvailableBackends()
	if len(backends) == 0 {
		t.Skip("no sandbox backends available")
	}

	ctx := context.Background()
	tmpDir := t.TempDir()

	veilBin := filepath.Join(tmpDir, "veil")
	repoRoot := findRepoRoot(t)
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", veilBin, "./cmd/veil")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build veil: %v\n%s", err, out)
	}

	echoAddr, stopEcho := startTimeoutEchoServer(t)
	defer stopEcho()

	projectDir := filepath.Join(tmpDir, "project")
	os.MkdirAll(projectDir, 0755)

	// Config with 120s timeout (enough for 10s test stream)
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(`routes: []
doppler:
  project: veilwarden
  config: dev
proxy:
  timeout_seconds: 120
sandbox:
  enabled: true
  backend: %s
  working_dir: %s
`, backends[0], projectDir)
	os.WriteFile(configPath, []byte(configContent), 0644)

	testScript := fmt.Sprintf(`#!/usr/bin/env python3
import urllib.request, json
url = "http://%s/stream?duration=10&interval=1000"
try:
    with urllib.request.urlopen(url, timeout=120) as resp:
        chunks = []
        for line in resp:
            line = line.decode().strip()
            if line:
                chunks.append(json.loads(line))
        if chunks and chunks[-1].get('complete'):
            print(json.dumps({"status": "complete", "chunks": len(chunks)}))
        else:
            print(json.dumps({"status": "incomplete", "chunks": len(chunks)}))
except Exception as e:
    print(json.dumps({"status": "error", "error": str(e)[:200]}))
`, echoAddr)

	scriptPath := filepath.Join(projectDir, "stream_test.py")
	os.WriteFile(scriptPath, []byte(testScript), 0755)

	timeoutCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, veilBin, "exec", "--config", configPath, "--",
		"python3", scriptPath)
	cmd.Env = append(os.Environ(), "DOPPLER_TOKEN="+dopplerToken)
	output, _ := cmd.CombinedOutput()

	result := extractJSON(string(output))
	var status struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	json.Unmarshal([]byte(result), &status)

	t.Logf("Stream test result: %s", result)

	if status.Status != "complete" {
		t.Errorf("Expected stream to complete with 120s timeout, got: %s (error: %s)",
			status.Status, status.Error)
		t.Logf("Full output: %s", output)
	}
}

// TestStreamingTimeout_DefaultTimeout verifies new 300s default works for longer streams.
func TestStreamingTimeout_DefaultTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e timeout test in short mode")
	}

	dopplerToken := os.Getenv("DOPPLER_TOKEN")
	if dopplerToken == "" {
		t.Skip("DOPPLER_TOKEN not set")
	}

	backends := detectAvailableBackends()
	if len(backends) == 0 {
		t.Skip("no sandbox backends available")
	}

	ctx := context.Background()
	tmpDir := t.TempDir()

	veilBin := filepath.Join(tmpDir, "veil")
	repoRoot := findRepoRoot(t)
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", veilBin, "./cmd/veil")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build veil: %v\n%s", err, out)
	}

	echoAddr, stopEcho := startTimeoutEchoServer(t)
	defer stopEcho()

	projectDir := filepath.Join(tmpDir, "project")
	os.MkdirAll(projectDir, 0755)

	// Config WITHOUT proxy section - uses 300s default
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(`routes: []
doppler:
  project: veilwarden
  config: dev
sandbox:
  enabled: true
  backend: %s
  working_dir: %s
`, backends[0], projectDir)
	os.WriteFile(configPath, []byte(configContent), 0644)

	// 35s stream would fail with old 30s default
	testScript := fmt.Sprintf(`#!/usr/bin/env python3
import urllib.request, json
url = "http://%s/stream?duration=35&interval=1000"
try:
    with urllib.request.urlopen(url, timeout=120) as resp:
        chunks = []
        for line in resp:
            line = line.decode().strip()
            if line:
                chunks.append(json.loads(line))
        if chunks and chunks[-1].get('complete'):
            print(json.dumps({"status": "complete", "chunks": len(chunks)}))
        else:
            print(json.dumps({"status": "incomplete", "chunks": len(chunks)}))
except Exception as e:
    print(json.dumps({"status": "error", "error": str(e)[:200]}))
`, echoAddr)

	scriptPath := filepath.Join(projectDir, "stream_test.py")
	os.WriteFile(scriptPath, []byte(testScript), 0755)

	timeoutCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, veilBin, "exec", "--config", configPath, "--",
		"python3", scriptPath)
	cmd.Env = append(os.Environ(), "DOPPLER_TOKEN="+dopplerToken)
	output, _ := cmd.CombinedOutput()

	result := extractJSON(string(output))
	var status struct {
		Status string `json:"status"`
	}
	json.Unmarshal([]byte(result), &status)

	t.Logf("Default timeout test result: %s", result)

	if status.Status != "complete" {
		t.Errorf("Expected 35s stream to complete with default 300s timeout, got: %s", status.Status)
		t.Logf("Full output: %s", output)
	}
}
