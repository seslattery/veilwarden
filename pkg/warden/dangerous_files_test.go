// pkg/warden/dangerous_files_test.go
package warden

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDangerousFilePatterns(t *testing.T) {
	patterns := DangerousFilePatterns()

	// Should have patterns for .env files (seatbelt regex format)
	assert.Contains(t, patterns, `.*/\.env$`)
	assert.Contains(t, patterns, `.*/\.env\..*`)
	assert.Contains(t, patterns, `^\.env$`)

	// Should have patterns for git hooks
	assert.Contains(t, patterns, `.*/\.git/hooks$`)
	assert.Contains(t, patterns, `.*/\.git/hooks/.*`)
	assert.Contains(t, patterns, `.*/\.git/config$`)

	// Should have patterns for credential files
	assert.Contains(t, patterns, `.*/\.npmrc$`)
	assert.Contains(t, patterns, `.*/\.pypirc$`)
	assert.Contains(t, patterns, `.*/\.aws/credentials$`)
	assert.Contains(t, patterns, `.*/\.docker/config\.json$`)
}

func TestIsDangerousPath(t *testing.T) {
	tests := []struct {
		path      string
		dangerous bool
	}{
		{".env", true},
		{".env.local", true},
		{"src/.env", true},
		{".git/hooks/pre-commit", true},
		{".git/config", true},
		{".npmrc", true},
		{"src/main.go", false},
		{".gitignore", false},
		{"environment.ts", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.dangerous, IsDangerousPath(tt.path))
		})
	}
}
