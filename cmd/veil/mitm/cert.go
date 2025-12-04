package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// EphemeralCA represents a short-lived certificate authority for MITM.
type EphemeralCA struct {
	CACert    *x509.Certificate
	CAKey     *rsa.PrivateKey
	CertPath  string
	sessionID string
}

// GenerateEphemeralCA creates a new ephemeral CA certificate and key.
// The certificate is valid for 1 hour and is written to a temp file.
func GenerateEphemeralCA(sessionID string) (*EphemeralCA, error) {
	// Generate RSA key for CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Generate random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create self-signed CA certificate
	caCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("VeilWarden Ephemeral CA %s", sessionID[:8]),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA cert: %w", err)
	}

	// Parse the DER-encoded certificate
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA cert: %w", err)
	}

	// Write cert to temp file
	tmpDir := os.TempDir()
	certPath := filepath.Join(tmpDir, fmt.Sprintf("veil-ca-%s.crt", sessionID))

	certFile, err := os.Create(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}); err != nil {
		return nil, fmt.Errorf("failed to encode cert: %w", err)
	}

	return &EphemeralCA{
		CACert:    caCert,
		CAKey:     caKey,
		CertPath:  certPath,
		sessionID: sessionID,
	}, nil
}

// Cleanup removes the temporary CA certificate file.
func (ca *EphemeralCA) Cleanup() error {
	if ca.CertPath == "" {
		return nil
	}
	if err := os.Remove(ca.CertPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove CA cert %s: %w", ca.CertPath, err)
	}
	ca.CertPath = ""
	return nil
}
