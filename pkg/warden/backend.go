package warden

import (
	"context"
	"io"
)

// Backend interface for pluggable sandbox implementations.
type Backend interface {
	Start(ctx context.Context, cfg *Config) (*Process, error)
}

// Process represents a running sandboxed process.
type Process struct {
	PID    int
	Stdin  io.WriteCloser
	Stdout io.ReadCloser
	Stderr io.ReadCloser
	Wait   func() error // Blocks until process exits, handles cleanup
}
