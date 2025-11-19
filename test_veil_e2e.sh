#!/bin/bash
set -e

echo "=== VeilWarden E2E Test ==="

# Build veil binary
echo "Building veil..."
go build -o veil ./cmd/veil

# Create test config
echo "Creating test config..."
./veil init --config-dir /tmp/veil-e2e-test

# Test 1: Verify env vars are set
echo ""
echo "Test 1: Environment variable injection"
OUTPUT=$(OPENAI_API_KEY=test-key ./veil exec --config /tmp/veil-e2e-test/config.yaml -- env 2>/dev/null | grep -c "HTTP_PROXY" || true)
if [ "$OUTPUT" -ge 1 ]; then
    echo "✓ HTTP_PROXY environment variable set"
else
    echo "✗ FAILED: HTTP_PROXY not set"
    exit 1
fi

# Test 2: Verify CA cert exists during execution
echo ""
echo "Test 2: CA certificate generation"
OUTPUT=$(./veil exec --config /tmp/veil-e2e-test/config.yaml -- bash -c 'test -f "$SSL_CERT_FILE" && echo exists' 2>/dev/null)
if [ "$OUTPUT" = "exists" ]; then
    echo "✓ CA certificate file exists during execution"
else
    echo "✗ FAILED: CA certificate not found"
    exit 1
fi

# Test 3: Verify proxy is listening
echo ""
echo "Test 3: Proxy server startup"
OUTPUT=$(./veil exec --verbose --config /tmp/veil-e2e-test/config.yaml -- echo "test" 2>&1 | grep -c "martian proxy listening" || true)
if [ "$OUTPUT" -ge 1 ]; then
    echo "✓ Proxy server started successfully"
else
    echo "✗ FAILED: Proxy server did not start"
    exit 1
fi

# Cleanup
rm -rf /tmp/veil-e2e-test
rm -f veil

echo ""
echo "=== All E2E Tests Passed! ==="
