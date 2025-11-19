package main

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/google/martian/v3"
	"github.com/google/martian/v3/mitm"
)

// MartianProxyConfig holds configuration for the Martian MITM proxy.
type MartianProxyConfig struct {
	SessionID   string
	CACert      *x509.Certificate
	CAKey       *rsa.PrivateKey
	RequireAuth bool
	Logger      *slog.Logger
}

// MartianProxyServer wraps a Martian proxy with VeilWarden configuration.
type MartianProxyServer struct {
	proxy       *martian.Proxy
	mitmConfig  *mitm.Config
	sessionID   string
	requireAuth bool
	logger      *slog.Logger
}

// NewMartianProxyServer creates a new Martian MITM proxy server.
func NewMartianProxyServer(cfg *MartianProxyConfig) (*MartianProxyServer, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Create Martian proxy
	proxy := martian.NewProxy()

	// If CA cert provided, setup MITM
	if cfg.CACert != nil && cfg.CAKey != nil {
		mc, err := mitm.NewConfig(cfg.CACert, cfg.CAKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create MITM config: %w", err)
		}

		mc.SetValidity(1 * time.Hour)
		mc.SetOrganization("VeilWarden MITM")

		proxy.SetMITM(mc)
	}

	proxy.SetTimeout(30 * time.Second)

	return &MartianProxyServer{
		proxy:       proxy,
		sessionID:   cfg.SessionID,
		requireAuth: cfg.RequireAuth,
		logger:      cfg.Logger,
	}, nil
}

// Serve starts the proxy server on the given listener.
func (s *MartianProxyServer) Serve(listener net.Listener) error {
	s.logger.Info("martian proxy listening", "addr", listener.Addr().String())
	return s.proxy.Serve(listener)
}
