package warden

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGlobToRegex(t *testing.T) {
	tests := []struct {
		name    string
		glob    string
		matches []string
		noMatch []string
	}{
		{
			name:    "single star",
			glob:    "/tmp/agent-*",
			matches: []string{"/tmp/agent-123", "/tmp/agent-foo"},
			noMatch: []string{"/tmp/agent-foo/bar", "/tmp/other"},
		},
		{
			name:    "double star",
			glob:    "/home/user/.config/**",
			matches: []string{"/home/user/.config/foo", "/home/user/.config/foo/bar"},
			noMatch: []string{"/home/user/.ssh"},
		},
		{
			name:    "question mark",
			glob:    "/tmp/file?.txt",
			matches: []string{"/tmp/file1.txt", "/tmp/fileA.txt"},
			noMatch: []string{"/tmp/file12.txt", "/tmp/file.txt"},
		},
		{
			name:    "special chars escaped",
			glob:    "/tmp/file.txt",
			matches: []string{"/tmp/file.txt"},
			noMatch: []string{"/tmp/fileXtxt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regex, err := globToRegex(tt.glob)
			require.NoError(t, err)

			re, err := regexp.Compile(regex)
			require.NoError(t, err, "regex should compile: %s", regex)

			for _, m := range tt.matches {
				assert.True(t, re.MatchString(m), "%s should match %s (regex: %s)", tt.glob, m, regex)
			}
			for _, m := range tt.noMatch {
				assert.False(t, re.MatchString(m), "%s should not match %s (regex: %s)", tt.glob, m, regex)
			}
		})
	}
}
