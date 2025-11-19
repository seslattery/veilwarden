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
