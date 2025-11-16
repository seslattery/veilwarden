#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export GOCACHE="${ROOT}/.gocache"

SESSION_SECRET="${SESSION_SECRET:-dev-secret}"
SECRET_ID="${DOPPLER_SECRET_ID:-ECHO_DOPPLER_SECRET}"
SECRET_VALUE="${ECHO_SECRET_VALUE:-demo-secret}"
MANUAL_SECRET_ID="${MANUAL_SECRET_ID:-ECHO_MANUAL_SECRET}"
ECHO_ADDR="${ECHO_ADDR:-127.0.0.1:${ECHO_PORT:-9091}}"
ECHO_MANUAL_ADDR="${ECHO_MANUAL_ADDR:-127.0.0.1:${ECHO_MANUAL_PORT:-9092}}"

DOPPLER_PROJECT="${DOPPLER_PROJECT:-veilwarden}"
DOPPLER_CONFIG="${DOPPLER_CONFIG:-dev_personal}"

if [[ -z "${DOPPLER_TOKEN:-}" ]]; then
	echo "error: DOPPLER_TOKEN must be set (export it before running this script)" >&2
	exit 1
fi

ECHO_LOG="$(mktemp -t veil-echo.XXXX.log)"
ECHO_MANUAL_LOG="$(mktemp -t veil-echo-manual.XXXX.log)"
PROXY_LOG="$(mktemp -t veil-proxy.XXXX.log)"
CONFIG_FILE="$(mktemp -t veil-doppler-config.XXXX.yaml)"
ECHO_PID=""
ECHO_MANUAL_PID=""
PROXY_PID=""

cleanup() {
	if [[ -n "${PROXY_PID}" ]]; then
		kill "${PROXY_PID}" >/dev/null 2>&1 || true
	fi
	if [[ -n "${ECHO_PID}" ]]; then
		kill "${ECHO_PID}" >/dev/null 2>&1 || true
	fi
	if [[ -n "${ECHO_MANUAL_PID}" ]]; then
		kill "${ECHO_MANUAL_PID}" >/dev/null 2>&1 || true
	fi
	rm -f "${CONFIG_FILE}"
	echo "Logs saved to:"
	echo "  echo (auto):   ${ECHO_LOG}"
	echo "  echo (manual): ${ECHO_MANUAL_LOG}"
	echo "  proxy:         ${PROXY_LOG}"
}
trap cleanup EXIT

cat >"${CONFIG_FILE}" <<EOF
routes:
  - upstream_host: ${ECHO_ADDR}
    upstream_scheme: http
    secret_id: ${SECRET_ID}
    inject_header: X-Doppler-Secret
    header_value_template: "{{secret}}"
  - upstream_host: ${ECHO_MANUAL_ADDR}
    upstream_scheme: http
    secret_id: ${MANUAL_SECRET_ID}
    inject_header: X-Manual-Secret
    header_value_template: "{{secret}}"
EOF

echo "Ensuring Doppler secret ${SECRET_ID} exists..."
printf "%s" "${SECRET_VALUE}" | doppler secrets set "${SECRET_ID}" \
  --no-interactive \
  --project "${DOPPLER_PROJECT}" \
  --config "${DOPPLER_CONFIG}" >/dev/null

echo "Checking if manual secret ${MANUAL_SECRET_ID} exists..."
if ! doppler secrets get "${MANUAL_SECRET_ID}" \
  --project "${DOPPLER_PROJECT}" \
  --config "${DOPPLER_CONFIG}" \
  --plain >/dev/null 2>&1; then
  echo "Creating ${MANUAL_SECRET_ID} with initial value 'manual-initial'..."
  printf "%s" "manual-initial" | doppler secrets set "${MANUAL_SECRET_ID}" \
    --no-interactive \
    --project "${DOPPLER_PROJECT}" \
    --config "${DOPPLER_CONFIG}" >/dev/null
  echo "You can change ${MANUAL_SECRET_ID} in the Doppler UI to test cache updates."
else
  echo "${MANUAL_SECRET_ID} already exists (not overwriting)."
fi

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

echo "Starting echo server (auto-updated) on ${ECHO_ADDR}..."
(cd "${ROOT}" && go run ./cmd/echo --listen "${ECHO_ADDR}" >>"${ECHO_LOG}" 2>&1) &
ECHO_PID=$!
wait_for_http "http://${ECHO_ADDR}" || { echo "echo server (auto) failed to start"; exit 1; }

echo "Starting echo server (manual) on ${ECHO_MANUAL_ADDR}..."
(cd "${ROOT}" && go run ./cmd/echo --listen "${ECHO_MANUAL_ADDR}" >>"${ECHO_MANUAL_LOG}" 2>&1) &
ECHO_MANUAL_PID=$!
wait_for_http "http://${ECHO_MANUAL_ADDR}" || { echo "echo server (manual) failed to start"; exit 1; }

echo "Starting veilwarden proxy (Doppler)..."
(cd "${ROOT}" && VEILWARDEN_SESSION_SECRET="${SESSION_SECRET}" \
	go run ./cmd/veilwarden \
		--config "${CONFIG_FILE}" \
		--doppler-token "${DOPPLER_TOKEN}" \
		--doppler-project "${DOPPLER_PROJECT}" \
		--doppler-config "${DOPPLER_CONFIG}" \
		--secret-cache-ttl "${SECRET_CACHE_TTL:-30s}" \
		--doppler-timeout "${DOPPLER_TIMEOUT:-5s}" >>"${PROXY_LOG}" 2>&1) &
PROXY_PID=$!
wait_for_http "http://127.0.0.1:8088/healthz" || { echo "proxy failed to start"; exit 1; }

echo "Sending test request to auto-updated secret route..."
curl -s -D - http://127.0.0.1:8088/echo-test \
  -H "X-Session-Secret: ${SESSION_SECRET}" \
  -H "X-Upstream-Host: ${ECHO_ADDR}" \
  -d 'hello=doppler' \
  | tee /tmp/veilwarden-doppler-response.txt

echo
echo "Sending test request to manual secret route..."
curl -s -D - http://127.0.0.1:8088/echo-test \
  -H "X-Session-Secret: ${SESSION_SECRET}" \
  -H "X-Upstream-Host: ${ECHO_MANUAL_ADDR}" \
  -d 'hello=manual' \
  | tee /tmp/veilwarden-manual-response.txt

echo
echo "Responses stored:"
echo "  Auto-updated: /tmp/veilwarden-doppler-response.txt (look for X-Doppler-Secret)"
echo "  Manual:       /tmp/veilwarden-manual-response.txt (look for X-Manual-Secret)"
echo
echo "To test cache expiry:"
echo "  1. Change ${MANUAL_SECRET_ID} in Doppler UI"
echo "  2. Wait ${SECRET_CACHE_TTL:-30s} (cache TTL)"
echo "  3. Run: curl -s http://127.0.0.1:8088/echo-test -H 'X-Session-Secret: ${SESSION_SECRET}' -H 'X-Upstream-Host: ${ECHO_MANUAL_ADDR}' | grep X-Manual-Secret"
echo
echo "Press Ctrl+C to stop servers."
wait
