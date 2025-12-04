//go:build !darwin

package warden

import (
	"context"
	"fmt"
)

// SeatbeltBackend is a stub for non-macOS platforms.
type SeatbeltBackend struct{}

func (s *SeatbeltBackend) Start(ctx context.Context, cfg *Config) (*Process, error) {
	return nil, fmt.Errorf("seatbelt only available on macOS")
}
