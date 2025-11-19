package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestSandboxFlag_ReturnsError(t *testing.T) {
	// Save and restore original value
	originalSandbox := execSandbox
	defer func() { execSandbox = originalSandbox }()

	execSandbox = true

	cmd := &cobra.Command{}
	err := runExec(cmd, []string{"echo", "test"})

	if err == nil {
		t.Fatal("expected error when sandbox flag is set")
	}

	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Fatalf("expected 'not yet implemented' in error, got: %v", err)
	}
}

func TestBuildProxyEnv_StripsDopplerToken(t *testing.T) {
	parentEnv := []string{
		"DOPPLER_TOKEN=dp.st.dev.secret123",
		"OPENAI_API_KEY=sk-test",
		"PATH=/usr/bin",
		"HOME=/home/user",
	}

	childEnv := buildProxyEnv(parentEnv, "http://localhost:8080", "/tmp/ca.crt")

	// DOPPLER_TOKEN should be stripped
	for _, e := range childEnv {
		if strings.HasPrefix(e, "DOPPLER_TOKEN=") {
			t.Fatal("DOPPLER_TOKEN should not be in child environment")
		}
	}

	// Other secrets should remain
	hasOpenAI := false
	hasPath := false
	for _, e := range childEnv {
		if strings.HasPrefix(e, "OPENAI_API_KEY=") {
			hasOpenAI = true
		}
		if strings.HasPrefix(e, "PATH=") {
			hasPath = true
		}
	}
	if !hasOpenAI {
		t.Fatal("OPENAI_API_KEY should remain in child environment")
	}
	if !hasPath {
		t.Fatal("PATH should remain in child environment")
	}

	// Proxy vars should be added
	hasHTTPProxy := false
	for _, e := range childEnv {
		if strings.HasPrefix(e, "HTTP_PROXY=") {
			hasHTTPProxy = true
		}
	}
	if !hasHTTPProxy {
		t.Fatal("HTTP_PROXY should be added to child environment")
	}
}
