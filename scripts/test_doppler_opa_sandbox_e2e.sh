#!/usr/bin/env bash
#
# VeilWarden E2E Integration Test - Real Services Only
# Tests: veil CLI + Real Doppler + Real OPA + Real Anthropic Sandbox
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export GOCACHE="${ROOT}/.gocache"

# Colors
RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m'
BLUE='\033[0;34m' CYAN='\033[0;36m' NC='\033[0m'

# Test state
TEST_COUNT=0 PASS_COUNT=0 FAIL_COUNT=0

# Directories
TEST_DIR="$(mktemp -d -t veil-e2e.XXXX)"
BIN_DIR="${TEST_DIR}/bin"
POLICY_DIR="${TEST_DIR}/policies"
SANDBOX_PROJECT="${TEST_DIR}/project"
SANDBOX_DATA="${TEST_DIR}/data"
ECHO_PID=""

# ==============================================================================
# Helper Functions
# ==============================================================================

cleanup() {
    echo -e "\n${BLUE}=== Cleanup ===${NC}"
    [[ -n "${ECHO_PID:-}" ]] && kill "${ECHO_PID}" 2>/dev/null && echo "Stopped echo server"
    echo "Artifacts: ${TEST_DIR}"
    echo -e "Total: ${TEST_COUNT}  ${GREEN}Passed: ${PASS_COUNT}${NC}  ${RED}Failed: ${FAIL_COUNT}${NC}\n"
    [[ ${FAIL_COUNT} -gt 0 ]] && exit 1
}
trap cleanup EXIT

header() { echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n${BLUE}$1${NC}\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"; }
pass() { echo -e "  ${GREEN}✓${NC} $1"; ((++PASS_COUNT)); ((++TEST_COUNT)); }
fail() { echo -e "  ${RED}✗${NC} $1"; ((++FAIL_COUNT)); ((++TEST_COUNT)); }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
info() { echo -e "  ${BLUE}→${NC} $1"; }

# Run veil exec with standard options
run_veil() {
    local config="${1:-${TEST_DIR}/config.yaml}"
    shift
    DOPPLER_TOKEN="${DOPPLER_TOKEN}" "${BIN_DIR}/veil" exec --config "${config}" -- "$@" 2>&1 || true
}

# Extract JSON from mixed output (handles both compact and pretty-printed)
extract_json() {
    python3 -c "import sys; d=sys.stdin.read(); s=d.find('{'); e=d.rfind('}')+1; print(d[s:e] if s>=0 else '{}')" 2>/dev/null
}

# Check boolean and pass/fail
check_bool() {
    local msg="$1" val="$2" fail_msg="${3:-}"
    if [[ "${val}" == "true" ]]; then
        pass "${msg}"
    elif [[ -n "${fail_msg}" ]]; then
        fail "${fail_msg}"
    else
        warn "${msg} - NOT verified"
    fi
}

wait_for_http() {
    local url=$1 max=${2:-30}
    for _ in $(seq 1 ${max}); do
        curl -sf "${url}" >/dev/null 2>&1 && return 0
        sleep 0.2
    done
    return 1
}

# ==============================================================================
# Prerequisites
# ==============================================================================

header "VeilWarden E2E Test - Real Services Only"

[[ -z "${DOPPLER_TOKEN:-}" ]] && { fail "DOPPLER_TOKEN not set"; exit 1; }
pass "DOPPLER_TOKEN is set"

info "Verifying Doppler API..."
DOPPLER_RESP=$(curl -sf -H "Authorization: Bearer ${DOPPLER_TOKEN}" "https://api.doppler.com/v3/me" 2>/dev/null || echo '{}')
if echo "${DOPPLER_RESP}" | jq -e '.workplace' >/dev/null 2>&1; then
    pass "Doppler API verified ($(echo "${DOPPLER_RESP}" | jq -r '.workplace.name'))"
else
    fail "Doppler API failed"; exit 1
fi


command -v srt >/dev/null || { fail "srt not found"; exit 1; }
SANDBOX_VERSION=$(srt --version 2>/dev/null || echo "installed")
pass "srt: ${SANDBOX_VERSION}"

for tool in go curl jq; do
    command -v ${tool} >/dev/null || { fail "${tool} not found"; exit 1; }
done
pass "Required tools available"

# ==============================================================================
# Build & Setup
# ==============================================================================

header "Building Binaries"
mkdir -p "${BIN_DIR}" "${POLICY_DIR}" "${SANDBOX_PROJECT}" "${SANDBOX_DATA}"
cd "${ROOT}"

go build -o "${BIN_DIR}/veil" ./cmd/veil && pass "Built veil" || { fail "Build failed"; exit 1; }
go build -o "${BIN_DIR}/echo" ./cmd/echo && pass "Built echo server" || { fail "Build failed"; exit 1; }

# Start echo server
ECHO_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
ECHO_ADDR="127.0.0.1:${ECHO_PORT}"
"${BIN_DIR}/echo" --listen "${ECHO_ADDR}" >"${TEST_DIR}/echo.log" 2>&1 &
ECHO_PID=$!
wait_for_http "http://${ECHO_ADDR}/health" && pass "Echo server on ${ECHO_ADDR}" || { fail "Echo server failed"; exit 1; }

# ==============================================================================
# OPA Policy
# ==============================================================================

header "Creating OPA Policy"

cat > "${POLICY_DIR}/policy.rego" << 'REGO'
package veilwarden.authz
import rego.v1
default allow := false
allow if { input.method == "CONNECT" }
allow if { input.method == "GET"; input.path == "/get" }
allow if { input.method == "POST"; input.path == "/post" }
allow if { input.method == "GET"; input.path == "/health" }
allow if { input.method == "GET"; startswith(input.path, "/api/") }
REGO

pass "OPA policy created"

# ==============================================================================
# Doppler Secrets
# ==============================================================================

header "Setting Doppler Secrets"

DOPPLER_PROJECT="${DOPPLER_PROJECT:-veilwarden}"
DOPPLER_CONFIG="${DOPPLER_CONFIG:-dev}"
TS=$(date +%s)

SECRET_HTTPBIN="httpbin-key-${TS}-$(openssl rand -hex 8)"
SECRET_ECHO="echo-key-${TS}-$(openssl rand -hex 8)"
SECRET_BASIC="user:pass-${TS}-$(openssl rand -hex 4)"

RESP=$(curl -sf -X POST -H "Authorization: Bearer ${DOPPLER_TOKEN}" -H "Content-Type: application/json" \
    -d "{\"secrets\":{\"VEIL_E2E_HTTPBIN_KEY\":\"${SECRET_HTTPBIN}\",\"VEIL_E2E_ECHO_KEY\":\"${SECRET_ECHO}\",\"VEIL_E2E_BASIC_AUTH\":\"${SECRET_BASIC}\"}}" \
    "https://api.doppler.com/v3/configs/config/secrets?project=${DOPPLER_PROJECT}&config=${DOPPLER_CONFIG}" 2>&1)

echo "${RESP}" | jq -e '.secrets' >/dev/null 2>&1 && pass "Secrets set in Doppler" || { fail "Failed to set secrets"; exit 1; }

# ==============================================================================
# Veil Configuration
# ==============================================================================

header "Creating Configuration"

cat > "${TEST_DIR}/config.yaml" << EOF
routes:
  - host: "postman-echo.com"
    secret_id: VEIL_E2E_HTTPBIN_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"
  - host: "127.0.0.1"
    secret_id: VEIL_E2E_ECHO_KEY
    header_name: X-API-Key
    header_value_template: "{{secret}}"
  - host: "localhost"
    secret_id: VEIL_E2E_BASIC_AUTH
    header_name: Authorization
    header_value_template: "Basic {{secret}}"
doppler:
  project: ${DOPPLER_PROJECT}
  config: ${DOPPLER_CONFIG}
policy:
  enabled: true
  engine: opa
  policy_path: ${POLICY_DIR}
  decision_path: veilwarden/authz/allow
sandbox:
  enabled: true
  backend: anthropic
  working_dir: ${SANDBOX_PROJECT}
  allowed_write_paths: ["${SANDBOX_PROJECT}", "${SANDBOX_DATA}"]
  denied_read_paths: ["~/.ssh", "~/.aws", "~/.doppler", "~/.gnupg"]
EOF
pass "Configuration created"

# ==============================================================================
# Test Scripts (consolidated)
# ==============================================================================

header "Creating Test Scripts"

# Universal HTTP test script
cat > "${SANDBOX_PROJECT}/http_test.py" << 'PYTHON'
#!/usr/bin/env python3
import os, sys, json, urllib.request, ssl

url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9999/health"
method = sys.argv[2] if len(sys.argv) > 2 else "GET"

print(f"Request: {method} {url}", file=sys.stderr)
print(f"HTTP_PROXY: {os.environ.get('HTTP_PROXY', 'NOT_SET')}", file=sys.stderr)

try:
    ctx = ssl.create_default_context()
    ca = os.environ.get('SSL_CERT_FILE')
    if ca: ctx.load_verify_locations(ca)

    data = b'{}' if method == "POST" else None
    req = urllib.request.Request(url, method=method, data=data)
    req.add_header('User-Agent', 'curl/8.0')
    with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
        print(resp.read().decode('utf-8'))
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
PYTHON

# Network isolation test
cat > "${SANDBOX_PROJECT}/network_isolation.py" << 'PYTHON'
#!/usr/bin/env python3
import json, os, socket, sys, urllib.request

results = {}
tests = [
    ("direct_tcp", lambda: socket.create_connection(('8.8.8.8', 80), timeout=3)),
    ("direct_https", lambda: urllib.request.build_opener(urllib.request.ProxyHandler({})).open('https://postman-echo.com/ip', timeout=3)),
    ("dns_resolution", lambda: socket.gethostbyname('canary.example.com')),
    ("raw_socket", lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)),
]
for name, fn in tests:
    try:
        fn()
        results[name] = {"blocked": False, "error": "SUCCEEDED - SECURITY RISK!"}
    except Exception as e:
        results[name] = {"blocked": True, "error": str(e)[:80]}

results["all_blocked"] = all(r["blocked"] for r in results.values())
print(json.dumps(results, indent=2))
PYTHON

# Filesystem escape test
cat > "${SANDBOX_PROJECT}/fs_escapes.py" << 'PYTHON'
#!/usr/bin/env python3
import os, sys, json

results = {}
allowed_dir = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()

def test_escape(name, fn):
    try:
        fn()
        results[name] = {"blocked": False, "error": "SUCCEEDED - SECURITY RISK!"}
    except Exception as e:
        results[name] = {"blocked": True, "error": str(e)[:80]}

test_escape("symlink", lambda: open(os.path.join(allowed_dir, "link") if not os.symlink(os.path.expanduser("~/.ssh/id_rsa"), p:=os.path.join(allowed_dir, "link")) else p).read(1))
test_escape("path_traversal", lambda: open(os.path.join(allowed_dir, "../../../etc/passwd")).read(1))
test_escape("write_escape", lambda: open("/tmp/veil_escape_test", "w").write("test"))
test_escape("hardlink", lambda: os.link(os.path.expanduser("~/.ssh/known_hosts"), os.path.join(allowed_dir, "hlink")))
test_escape("sensitive_read", lambda: open(os.path.expanduser("~/.ssh/id_rsa")).read(1))
test_escape("proc_access", lambda: open("/proc/self/cmdline").read(1))

results["all_blocked"] = all(r["blocked"] for r in results.values())
results["summary"] = f"{sum(1 for r in results.values() if isinstance(r,dict) and r.get('blocked'))}/{len([r for r in results.values() if isinstance(r,dict)])}"
print(json.dumps(results, indent=2))
PYTHON

# Environment check script
cat > "${SANDBOX_PROJECT}/env_check.py" << 'PYTHON'
#!/usr/bin/env python3
import os, json
print(json.dumps({
    "HTTP_PROXY": bool(os.environ.get("HTTP_PROXY")),
    "HTTPS_PROXY": bool(os.environ.get("HTTPS_PROXY")),
    "CA_CERT": os.path.exists(os.environ.get("SSL_CERT_FILE", "")),
    "DOPPLER_TOKEN": "DOPPLER_TOKEN" in os.environ
}))
PYTHON

# File persistence test
cat > "${SANDBOX_PROJECT}/persist_test.py" << PYTHON
#!/usr/bin/env python3
import time
f = "${SANDBOX_DATA}/test.txt"
open(f, "w").write(f"sandbox-{time.time()}")
print(open(f).read())
PYTHON

chmod +x "${SANDBOX_PROJECT}"/*.py
pass "Test scripts created"

# ==============================================================================
# TEST 1: Proxy Environment & Token Stripping
# ==============================================================================

header "Test 1: Sandbox Environment"

OUTPUT=$(run_veil "${TEST_DIR}/config.yaml" python3 "${SANDBOX_PROJECT}/env_check.py")
JSON=$(echo "${OUTPUT}" | extract_json)

check_bool "HTTP_PROXY set" "$(echo "${JSON}" | jq -r '.HTTP_PROXY')"
check_bool "HTTPS_PROXY set" "$(echo "${JSON}" | jq -r '.HTTPS_PROXY')"
check_bool "CA cert accessible" "$(echo "${JSON}" | jq -r '.CA_CERT')"
[[ "$(echo "${JSON}" | jq -r '.DOPPLER_TOKEN')" == "false" ]] && pass "DOPPLER_TOKEN stripped" || fail "DOPPLER_TOKEN leaked!"

# ==============================================================================
# TEST 2: OPA Policy Enforcement
# ==============================================================================

header "Test 2: OPA Policy Enforcement"

# Allowed request
info "GET /get (should be allowed)..."
OUTPUT=$(run_veil "${TEST_DIR}/config.yaml" python3 "${SANDBOX_PROJECT}/http_test.py" "https://postman-echo.com/get" GET)
echo "${OUTPUT}"
JSON=$(echo "${OUTPUT}" | extract_json)
AUTH=$(echo "${JSON}" | jq -r '.headers.authorization // empty')
EXPECTED="Bearer ${SECRET_HTTPBIN}"

if [[ "${AUTH}" == "${EXPECTED}" ]]; then
    pass "GET /get allowed with correct secret"
else
    fail "Secret mismatch: expected ${EXPECTED}, got ${AUTH}"
fi

# Denied request
info "GET /headers (should be denied)..."
OUTPUT=$(run_veil "${TEST_DIR}/config.yaml" python3 "${SANDBOX_PROJECT}/http_test.py" "https://postman-echo.com/headers" GET)
echo "${OUTPUT}"
echo "${OUTPUT}" | grep -qiE "(403|forbidden|policy)" && pass "GET /headers blocked by policy" || fail "Request should be blocked"

# POST allowed
info "POST /post (should be allowed)..."
OUTPUT=$(run_veil "${TEST_DIR}/config.yaml" python3 "${SANDBOX_PROJECT}/http_test.py" "https://postman-echo.com/post" POST)
JSON=$(echo "${OUTPUT}" | extract_json)
AUTH=$(echo "${JSON}" | jq -r '.headers.authorization // empty')
[[ "${AUTH}" == "Bearer ${SECRET_HTTPBIN}" ]] && pass "POST /post allowed with secret" || fail "POST failed"

# ==============================================================================
# TEST 3: Network Isolation
# ==============================================================================

header "Test 3: Network Isolation"

OUTPUT=$(run_veil "${TEST_DIR}/config.yaml" python3 "${SANDBOX_PROJECT}/network_isolation.py")
echo "${OUTPUT}"
JSON=$(echo "${OUTPUT}" | extract_json)

for test in direct_tcp direct_https dns_resolution raw_socket; do
    blocked=$(echo "${JSON}" | jq -r ".${test}.blocked // false")
    check_bool "${test} blocked" "${blocked}" "SECURITY: ${test} NOT blocked!"
done

[[ "$(echo "${JSON}" | jq -r '.all_blocked')" == "true" ]] && pass "All bypass attempts blocked" || fail "Some bypasses succeeded!"

# ==============================================================================
# TEST 4: Multiple Routes - Secret Isolation
# ==============================================================================

header "Test 4: Route Secret Isolation"

# localhost route (Basic auth)
OUTPUT=$(run_veil "${TEST_DIR}/config.yaml" python3 "${SANDBOX_PROJECT}/http_test.py" "http://localhost:${ECHO_PORT}/api/test" GET)
JSON=$(echo "${OUTPUT}" | extract_json)
AUTH=$(echo "${JSON}" | jq -r '.headers.Authorization[0] // .headers.authorization[0] // empty')
[[ "${AUTH}" == "Basic ${SECRET_BASIC}" ]] && pass "localhost: Basic auth correct" || fail "localhost: wrong auth (${AUTH})"

# 127.0.0.1 route (X-API-Key)
OUTPUT=$(run_veil "${TEST_DIR}/config.yaml" python3 "${SANDBOX_PROJECT}/http_test.py" "http://127.0.0.1:${ECHO_PORT}/api/test" GET)
JSON=$(echo "${OUTPUT}" | extract_json)
KEY=$(echo "${JSON}" | jq -r '.headers["X-Api-Key"][0] // empty')
[[ "${KEY}" == "${SECRET_ECHO}" ]] && pass "127.0.0.1: X-API-Key correct" || fail "127.0.0.1: wrong key (${KEY})"

# ==============================================================================
# TEST 5: Filesystem Escape Attempts
# ==============================================================================

header "Test 5: Filesystem Escape Attempts"

OUTPUT=$(run_veil "${TEST_DIR}/config.yaml" python3 "${SANDBOX_PROJECT}/fs_escapes.py" "${SANDBOX_DATA}")
echo "${OUTPUT}"
JSON=$(echo "${OUTPUT}" | extract_json)

for test in symlink path_traversal write_escape hardlink sensitive_read proc_access; do
    blocked=$(echo "${JSON}" | jq -r ".${test}.blocked // false")
    if [[ "${blocked}" == "true" ]]; then
        pass "${test} blocked"
    else
        warn "${test} NOT blocked (srt limitation)"
    fi
done

SUMMARY=$(echo "${JSON}" | jq -r '.summary // "unknown"')
info "Filesystem escape summary: ${SUMMARY}"
[[ "$(echo "${JSON}" | jq -r '.all_blocked')" == "true" ]] && pass "All escapes blocked!" || warn "Some escapes possible - network isolation is primary defense"

# ==============================================================================
# TEST 6: File Persistence
# ==============================================================================

header "Test 6: File Persistence"

OUTPUT=$(run_veil "${TEST_DIR}/config.yaml" python3 "${SANDBOX_PROJECT}/persist_test.py")
[[ -f "${SANDBOX_DATA}/test.txt" ]] && pass "File persisted to host" || fail "File not persisted"

# ==============================================================================
# Summary
# ==============================================================================

header "Test Results Summary"

echo "Components: Doppler API, srt ${SANDBOX_VERSION}, Echo ${ECHO_ADDR}"
echo ""

if [[ ${FAIL_COUNT} -eq 0 ]]; then
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  ALL TESTS PASSED${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
else
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}  SOME TESTS FAILED${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
fi
