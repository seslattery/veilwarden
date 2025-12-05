//go:build darwin

package warden

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/term"
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

	// Use PTY for interactive shells
	if cfg.EnablePTY {
		return startWithPTY(cmd, profilePath)
	}

	return startWithPipes(cmd, profilePath)
}

// startWithPTY starts the command with a pseudo-terminal for interactive use.
func startWithPTY(cmd *exec.Cmd, profilePath string) (*Process, error) {
	// Start command with PTY
	ptmx, err := pty.Start(cmd)
	if err != nil {
		os.Remove(profilePath)
		return nil, fmt.Errorf("failed to start with pty: %w", err)
	}

	// Handle terminal resize
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			if err := pty.InheritSize(os.Stdin, ptmx); err != nil {
				// Ignore errors - terminal might not support resize
			}
		}
	}()
	ch <- syscall.SIGWINCH // Initial resize

	// Set stdin to raw mode for proper terminal handling
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		// Not a terminal, fall back to normal mode
		oldState = nil
	}

	// Copy stdin to pty
	go func() {
		io.Copy(ptmx, os.Stdin)
	}()

	return &Process{
		PID:    cmd.Process.Pid,
		Stdin:  ptmx,
		Stdout: ptmx,
		Stderr: io.NopCloser(&nilReader{}), // PTY combines stdout/stderr
		Wait: func() error {
			err := cmd.Wait()
			os.Remove(profilePath)
			signal.Stop(ch)
			close(ch)
			if oldState != nil {
				term.Restore(int(os.Stdin.Fd()), oldState)
			}
			return err
		},
	}, nil
}

// nilReader is an io.Reader that always returns EOF.
type nilReader struct{}

func (r *nilReader) Read(p []byte) (n int, err error) {
	return 0, io.EOF
}

// startWithPipes starts the command with standard pipes (non-interactive).
func startWithPipes(cmd *exec.Cmd, profilePath string) (*Process, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		os.Remove(profilePath)
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		os.Remove(profilePath)
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		os.Remove(profilePath)
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
			os.Remove(profilePath)
			return err
		},
	}, nil
}
