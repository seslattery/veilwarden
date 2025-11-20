package mitm

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateEphemeralCA(t *testing.T) {
	sessionID := "test-session-123"

	ca, err := GenerateEphemeralCA(sessionID)
	require.NoError(t, err)
	defer ca.Cleanup()

	// Verify CA cert properties
	assert.True(t, ca.CACert.IsCA, "certificate should be CA")
	assert.NotNil(t, ca.CAKey, "CA key should be generated")

	// Verify validity period is 1 hour
	validity := ca.CACert.NotAfter.Sub(ca.CACert.NotBefore)
	assert.Equal(t, 1*time.Hour, validity, "CA should be valid for 1 hour")

	// Verify cert file exists
	_, err = os.Stat(ca.CertPath)
	assert.NoError(t, err, "cert file should exist")

	// Verify cleanup removes cert
	ca.Cleanup()
	_, err = os.Stat(ca.CertPath)
	assert.True(t, os.IsNotExist(err), "cert file should be removed after cleanup")
}

func TestGenerateEphemeralCA_UniqueCerts(t *testing.T) {
	ca1, err := GenerateEphemeralCA("session-1")
	require.NoError(t, err)
	defer ca1.Cleanup()

	ca2, err := GenerateEphemeralCA("session-2")
	require.NoError(t, err)
	defer ca2.Cleanup()

	// Verify different sessions get different certs
	assert.NotEqual(t, ca1.CertPath, ca2.CertPath, "different sessions should have different cert paths")
	assert.NotEqual(t, ca1.CACert.SerialNumber, ca2.CACert.SerialNumber, "different sessions should have different serial numbers")
}
