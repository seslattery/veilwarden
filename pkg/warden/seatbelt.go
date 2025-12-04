//go:build darwin

package warden

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
)

// SeatbeltBackend implements sandbox using macOS seatbelt (sandbox-exec).
type SeatbeltBackend struct{}

// Start launches a sandboxed process using sandbox-exec.
func (s *SeatbeltBackend) Start(ctx context.Context, cfg *Config) (*Process, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	profile, err := generateSeatbeltProfile(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate profile: %w", err)
	}

	if cfg.Debug {
		log.Printf("Seatbelt profile:\n%s", profile)
	}

	// Write profile to temp file (more reliable than -p inline)
	profileFile, err := os.CreateTemp("", "veil-seatbelt-*.sb")
	if err != nil {
		return nil, fmt.Errorf("failed to create profile file: %w", err)
	}
	profilePath := profileFile.Name()
	if _, err := profileFile.WriteString(profile); err != nil {
		os.Remove(profilePath)
		return nil, fmt.Errorf("failed to write profile: %w", err)
	}
	if err := profileFile.Sync(); err != nil {
		os.Remove(profilePath)
		return nil, fmt.Errorf("failed to sync profile: %w", err)
	}
	profileFile.Close()

	// Execute command using -f (file) instead of -p (inline)
	args := append([]string{"-f", profilePath}, cfg.Command...)

	// Find sandbox-exec path
	sandboxExecPath, err := exec.LookPath("sandbox-exec")
	if err != nil {
		os.Remove(profilePath)
		return nil, fmt.Errorf("sandbox-exec not found: %w", err)
	}

	cmd := exec.CommandContext(ctx, sandboxExecPath, args...)
	cmd.Env = cfg.Env
	cmd.Dir = cfg.WorkingDir

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

	if err := cmd.Start(); err != nil {
		os.Remove(profilePath)
		return nil, fmt.Errorf("failed to start sandbox-exec: %w", err)
	}

	return &Process{
		PID:    cmd.Process.Pid,
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		Wait: func() error {
			err := cmd.Wait()
			os.Remove(profilePath) // Clean up temp file
			return err
		},
	}, nil
}
