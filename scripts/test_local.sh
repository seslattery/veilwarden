#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export GOCACHE="${ROOT}/.gocache"
SESSION_SECRET="${SESSION_SECRET:-dev-secret}"
ECHO_ADDR="${ECHO_ADDR:-127.0.0.1:${ECHO_PORT:-9090}}"

ECHO_LOG="$(mktemp -t veil-echo.XXXX.log)"
PROXY_LOG="$(mktemp -t veil-proxy.XXXX.log)"
CONFIG_FILE="$(mktemp -t veil-config.XXXX.yaml)"
ECHO_PID=""
PROXY_PID=""

cleanup() {
	if [[ -n "${PROXY_PID}" ]]; then
		kill "${PROXY_PID}" >/dev/null 2>&1 || true
	fi
	if [[ -n "${ECHO_PID}" ]]; then
		kill "${ECHO_PID}" >/dev/null 2>&1 || true
	fi
	if [[ -f "${CONFIG_FILE}" ]]; then
		rm -f "${CONFIG_FILE}"
	fi
	echo "Logs saved to:"
	echo "  echo:  ${ECHO_LOG}"
	echo "  proxy: ${PROXY_LOG}"
}
trap cleanup EXIT

cat >"${CONFIG_FILE}" <<EOF
secrets:
  - id: echo-token
    value: demo-token

routes:
  - upstream_host: ${ECHO_ADDR}
    upstream_scheme: http
    secret_id: echo-token
    inject_header: Authorization
    header_value_template: "Bearer {{secret}}"
EOF

wait_for_http() {
	local url=$1
	for _ in {1..50}; do
		if curl -fs "${url}" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	return 1
}

echo "Starting echo server on ${ECHO_ADDR}..."
(cd "${ROOT}" && ECHO_ADDR="${ECHO_ADDR}" go run ./cmd/echo --listen "${ECHO_ADDR}" >>"${ECHO_LOG}" 2>&1) &
ECHO_PID=$!
wait_for_http "http://${ECHO_ADDR}" || { echo "echo server failed to start"; exit 1; }

echo "Starting veilwarden proxy..."
(cd "${ROOT}" && VEILWARDEN_SESSION_SECRET="${SESSION_SECRET}" go run ./cmd/veilwarden --config "${CONFIG_FILE}" >>"${PROXY_LOG}" 2>&1) &
PROXY_PID=$!
wait_for_http "http://127.0.0.1:8088/healthz" || { echo "proxy failed to start"; exit 1; }

echo "Sending test request through proxy..."
curl -s -D - -X POST http://127.0.0.1:8088/test \
  -H "X-Session-Secret: ${SESSION_SECRET}" \
  -H "X-Upstream-Host: ${ECHO_ADDR}" \
  -d 'hello=world'

echo
echo "Press Ctrl+C to stop servers or inspect logs listed above."
wait
