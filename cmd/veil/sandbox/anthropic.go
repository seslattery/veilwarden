package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type AnthropicBackend struct {
	cliPath string // Path to anthropic-sandbox binary
}

// NewAnthropicBackend creates a new Anthropic sandbox backend
func NewAnthropicBackend() (*AnthropicBackend, error) {
	// Check if anthropic-sandbox CLI exists
	cliPath, err := exec.LookPath("anthropic-sandbox")
	if err != nil {
		return nil, fmt.Errorf(
			"anthropic-sandbox CLI not found in PATH.\n\n" +
				"To install:\n" +
				"  1. Visit: https://github.com/anthropics/sandbox\n" +
				"  2. Follow installation instructions\n" +
				"  3. Verify: anthropic-sandbox --version\n\n" +
				"Alternatively, disable sandboxing:\n" +
				"  - Use flag: veil exec --no-sandbox\n" +
				"  - Or in config: sandbox.enabled: false")
	}

	return &AnthropicBackend{cliPath: cliPath}, nil
}

// Start launches the sandboxed process
func (a *AnthropicBackend) Start(ctx context.Context, cfg *Config) (*Process, error) {
	// Validate config first
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	args := a.buildArgs(cfg)

	cmd := exec.CommandContext(ctx, a.cliPath, args...)

	// Setup stdio pipes
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the sandbox process
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start sandbox: %w", err)
	}

	return &Process{
		PID:    cmd.Process.Pid,
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		Wait: func() error {
			err := cmd.Wait()
			stdin.Close()
			return err
		},
	}, nil
}

// buildArgs constructs the CLI arguments for anthropic-sandbox
func (a *AnthropicBackend) buildArgs(cfg *Config) []string {
	args := []string{"run"}

	// Add mounts
	for _, m := range cfg.Mounts {
		hostPath := expandPath(m.HostPath)
		flag := fmt.Sprintf("--mount=%s:%s", hostPath, m.ContainerPath)
		if m.ReadOnly {
			flag += ":ro"
		}
		args = append(args, flag)
	}

	// Add environment variables
	for _, e := range cfg.Env {
		args = append(args, "--env", e)
	}

	// Working directory
	if cfg.WorkingDir != "" {
		args = append(args, "--workdir", cfg.WorkingDir)
	}

	// Command separator and actual command
	args = append(args, "--")
	args = append(args, cfg.Command...)

	return args
}

// expandPath expands ~ to home directory
func expandPath(path string) string {
	if len(path) == 0 {
		return path
	}

	if path[0] == '~' {
		home, err := os.UserHomeDir()
		if err == nil {
			// Replace only the leading ~
			if len(path) == 1 {
				return home
			}
			if path[1] == '/' {
				return filepath.Join(home, path[2:])
			}
		}
	}

	return path
}
