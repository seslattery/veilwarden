package warden

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"tilde alone", "~", home},
		{"tilde with path", "~/.ssh", filepath.Join(home, ".ssh")},
		{"absolute path", "/tmp/foo", "/tmp/foo"},
		{"relative path", "./foo", "./foo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandHome(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsGlob(t *testing.T) {
	tests := []struct {
		path   string
		isGlob bool
	}{
		{"/tmp/foo", false},
		{"/tmp/foo*", true},
		{"/tmp/foo-*", true},
		{"/tmp/**/bar", true},
		{"/tmp/foo?bar", true},
		{"/tmp/[abc]", false}, // [] not allowed for safety
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.isGlob, isGlob(tt.path))
		})
	}
}

func TestIsSensitivePath(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"root", "/", true},
		{"etc", "/etc", true},
		{"usr", "/usr", true},
		{"var", "/var", true},
		{"bin", "/bin", true},
		{"sbin", "/sbin", true},
		{"lib", "/lib", true},
		{"root dir", "/root", true},
		{"home dir", "/home", true},
		{"home ssh", filepath.Join(home, ".ssh"), true},
		{"home aws", filepath.Join(home, ".aws"), true},
		{"home gnupg", filepath.Join(home, ".gnupg"), true},
		{"home kube", filepath.Join(home, ".kube"), true},
		{"home docker", filepath.Join(home, ".docker"), true},
		{"home subdir of ssh", filepath.Join(home, ".ssh/keys"), true},
		{"home subdir of aws", filepath.Join(home, ".aws/credentials"), true},
		{"tmp", "/tmp", false},
		{"home projects", filepath.Join(home, "projects"), false},
		{"home dev", filepath.Join(home, "dev"), false},
		{"usr local bin", "/usr/local/bin", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSensitivePath(tt.path)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidatePathSafety(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		isAllowRule bool
		wantErr     string
	}{
		{"literal path ok", "/tmp/foo", true, ""},
		{"path traversal blocked", "/tmp/../etc", false, "traversal"},
		{"root wildcard blocked", "/*", false, "root wildcard"},
		{"double star root blocked", "/**", false, "root wildcard"},
		{"regex injection blocked", "/tmp/(?.*)", false, "regex metacharacter"},
		{"allow glob needs depth", "/a/*", true, "2 directory"},
		{"allow glob ok with depth", "/tmp/project/*", true, ""},
		{"allow double star blocked", "/tmp/**", true, "**"},
		{"deny glob ok", "/tmp/**", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePathSafety(tt.path, tt.isAllowRule)
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestExtractLiteralPrefix(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{"no glob", "/tmp/foo/bar", "/tmp/foo/bar"},
		{"single star", "/tmp/agent-*", "/tmp"},
		{"double star", "/home/user/.config/**", "/home/user/.config"},
		{"question mark", "/tmp/file?.txt", "/tmp"},
		{"bracket", "/tmp/[abc]", "/tmp"},
		{"glob at end", "/tmp/project/*", "/tmp/project"},
		{"glob in middle", "/tmp/*/foo", "/tmp"},
		{"no slash before glob", "*.txt", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractLiteralPrefix(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidatePathSafety_RegexInjection(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
	}{
		{"/tmp/safe", false},
		{"/tmp/file.txt", false},
		{"/tmp/glob*", false},  // globs allowed in non-allow rules
		{"/tmp/glob?", false},  // globs allowed in non-allow rules
		{"/tmp/(?:regex)", true},
		{"/tmp/\\d+", true},
		{"/tmp/{1,2}", true},
		// These should now also be blocked:
		{"/tmp/[a-z]+", true},
		{"/tmp/file|other", true},
		{"/tmp/^start", true},
		{"/tmp/end$", true},
		{"/tmp/test+", true},
		{"/tmp/]bracket", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			err := validatePathSafety(tt.path, false)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExpandPath_EdgeCases(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string", "", ""},
		{"just tilde", "~", home},
		{"tilde slash", "~/", home},
		{"tilde with path", "~/foo/bar", filepath.Join(home, "foo/bar")},
		{"no tilde", "/absolute/path", "/absolute/path"},
		{"tilde in middle", "/path/~file", "/path/~file"}, // Should NOT expand
		{"other user tilde", "~otheruser/path", "~otheruser/path"}, // Should NOT expand
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExpandPath(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}
