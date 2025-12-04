package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpandPath(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantStart string
	}{
		{
			name:      "tilde expansion",
			input:     "~/project",
			wantStart: "/", // Should expand to absolute path starting with /
		},
		{
			name:      "absolute path unchanged",
			input:     "/tmp/data",
			wantStart: "/tmp/data",
		},
		{
			name:      "relative path unchanged",
			input:     "./project",
			wantStart: "./project",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandPath(tt.input)
			assert.True(t, len(result) > 0)

			if tt.input == "~/project" {
				// Should not contain tilde after expansion
				assert.NotContains(t, result, "~")
				// Should be absolute
				assert.True(t, result[0] == '/')
			} else {
				assert.Equal(t, tt.wantStart, result)
			}
		})
	}
}

func TestNewAnthropicBackend(t *testing.T) {
	backend, err := NewAnthropicBackend()
	if err != nil {
		t.Skip("srt not installed")
	}
	assert.NotNil(t, backend)
	assert.Contains(t, backend.cliPath, "srt")
}
