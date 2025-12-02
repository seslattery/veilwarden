package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnthropicBackend_BuildArgs(t *testing.T) {
	backend := &AnthropicBackend{cliPath: "anthropic-sandbox"}
	cfg := &Config{
		Command: []string{"python", "test.py"},
		Env: []string{
			"HTTP_PROXY=http://localhost:8080",
			"PATH=/usr/bin",
		},
		Mounts: []Mount{
			{HostPath: "/tmp/data", ContainerPath: "/data", ReadOnly: true},
			{HostPath: "/tmp/project", ContainerPath: "/workspace", ReadOnly: false},
		},
		WorkingDir: "/workspace",
	}

	args := backend.buildArgs(cfg)

	// Verify structure: run [mounts] [env] [workdir] -- command
	assert.Contains(t, args, "run")
	assert.Contains(t, args, "--")

	// Verify mounts (format may vary, check both are present)
	mountArgs := findMountArgs(args)
	assert.Len(t, mountArgs, 2)

	// Verify environment
	envArgs := findEnvArgs(args)
	assert.Contains(t, envArgs, "HTTP_PROXY=http://localhost:8080")
	assert.Contains(t, envArgs, "PATH=/usr/bin")

	// Verify working directory
	assert.Contains(t, args, "--workdir")
	workdirIdx := indexOf(args, "--workdir")
	require.Greater(t, workdirIdx, -1)
	require.Less(t, workdirIdx+1, len(args))
	assert.Equal(t, "/workspace", args[workdirIdx+1])

	// Verify command comes after --
	sepIdx := indexOf(args, "--")
	require.Greater(t, sepIdx, -1)
	cmdArgs := args[sepIdx+1:]
	assert.Equal(t, []string{"python", "test.py"}, cmdArgs)
}

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

// Helper functions for tests

func findMountArgs(args []string) []string {
	var mounts []string
	for _, arg := range args {
		if len(arg) > 8 && arg[:8] == "--mount=" {
			mounts = append(mounts, arg[8:])
		}
	}
	return mounts
}

func findEnvArgs(args []string) []string {
	var envs []string
	for i, arg := range args {
		if arg == "--env" && i+1 < len(args) {
			envs = append(envs, args[i+1])
		}
	}
	return envs
}

func indexOf(slice []string, target string) int {
	for i, v := range slice {
		if v == target {
			return i
		}
	}
	return -1
}
