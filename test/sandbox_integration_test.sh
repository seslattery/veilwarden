#!/bin/bash
# Integration test for sandbox functionality
# Requires: anthropic-sandbox CLI installed

set -e

echo "=== VeilWarden Sandbox Integration Test ==="

# Check if anthropic-sandbox is installed
if ! command -v anthropic-sandbox &> /dev/null; then
    echo "SKIP: anthropic-sandbox CLI not installed"
    echo "Install from: https://github.com/anthropics/sandbox"
    exit 0
fi

# Setup test environment
export TEST_API_KEY=sk-test-key-12345
TEST_DIR=$(mktemp -d)
cd "$TEST_DIR"
echo "Test directory: $TEST_DIR"

# Create test agent
cat > agent.py <<'EOF'
import os
import sys

# Test 1: Try to read sensitive file (should fail)
print("Test 1: Checking filesystem isolation...")
try:
    with open(os.path.expanduser("~/.ssh/id_rsa"), "r") as f:
        print("ERROR: Could read SSH key! Sandbox not working.")
        sys.exit(1)
except FileNotFoundError:
    print("✓ Cannot access ~/.ssh/id_rsa (expected)")
except PermissionError:
    print("✓ Cannot access ~/.ssh/id_rsa (expected)")

# Test 2: Verify we can access mounted workspace
print("\nTest 2: Checking mounted workspace...")
try:
    with open("/workspace/test.txt", "w") as f:
        f.write("sandbox test")
    print("✓ Can write to /workspace")
except Exception as e:
    print(f"ERROR: Cannot write to workspace: {e}")
    sys.exit(1)

# Test 3: Verify HTTP_PROXY is set
print("\nTest 3: Checking proxy environment...")
if "HTTP_PROXY" not in os.environ:
    print("ERROR: HTTP_PROXY not set")
    sys.exit(1)
print(f"✓ HTTP_PROXY set: {os.environ['HTTP_PROXY']}")

print("\n✓ All checks passed")
EOF

# Create veil config
cat > config.yaml <<EOF
routes:
  - host: example.com
    secret_id: TEST_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

sandbox:
  enabled: true
  backend: anthropic
  working_dir: /workspace
  mounts:
    - host: .
      container: /workspace
      readonly: false
EOF

# Build veil
echo -e "\nBuilding veil..."
cd - > /dev/null
go build -o /tmp/veil ./cmd/veil

# Run test
echo -e "\nRunning sandboxed agent..."
cd "$TEST_DIR"
/tmp/veil exec --config config.yaml -- python /workspace/agent.py

# Verify file persisted
if [ -f test.txt ]; then
    echo "✓ File persisted from sandbox"
    cat test.txt
else
    echo "ERROR: File not persisted"
    exit 1
fi

# Cleanup
cd - > /dev/null
rm -rf "$TEST_DIR"
rm -f /tmp/veil

echo -e "\n=== Sandbox Integration Test PASSED ==="
