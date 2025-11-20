# Doppler Integration E2E Tests

This directory contains two E2E tests for the Doppler integration with veil CLI.

## Test 1: Mock Doppler Server (No Credentials Required)

**File:** `test_veil_doppler_mock_e2e.sh`

This test runs completely locally with a Python mock server simulating the Doppler API.

### Usage:

```bash
./test_veil_doppler_mock_e2e.sh
```

### What it proves:

✅ Veil CLI reads Doppler configuration from `config.yaml`
✅ Veil calls Doppler API to fetch secrets
✅ Secrets are injected into HTTP Authorization headers
✅ MITM proxy intercepts and modifies requests
✅ Echo server receives requests with injected headers
✅ Secrets come from Doppler API, NOT environment variables
✅ Cache is functioning

### Test Output Example:

```
✅ SUCCESS: Authorization header injected from mock Doppler API!
   Expected: Bearer veil-doppler-mock-secret-xyz789
   Got:      Bearer veil-doppler-mock-secret-xyz789

Mock Doppler API was called 3 times total.
```

### Logs:

The test shows echo server and mock Doppler logs at the end:

```
Mock Doppler log contents:
---
[1] Request: /v3/configs/config/secret?project=mock-project&config=mock-config&name=VEIL_TEST_API_KEY
[1] ✓ Served secret: VEIL_TEST_API_KEY = veil-doppler-mock-secret-xyz789
---
```

## Test 2: Real Doppler API (Requires Credentials)

**File:** `test_veil_doppler_e2e.sh`

This test uses the actual Doppler API to fetch secrets.

### Prerequisites:

1. Doppler account with a project and config
2. `DOPPLER_TOKEN` environment variable set
3. `doppler` CLI installed (for setting secrets)

### Usage:

```bash
# Set your Doppler token
export DOPPLER_TOKEN="dp.st.dev.xxxxx"

# Optional: customize project/config
export DOPPLER_PROJECT="veilwarden"
export DOPPLER_CONFIG="dev_personal"

# Run the test
./test_veil_doppler_e2e.sh
```

### What the test does:

1. Sets a secret in your Doppler project: `VEIL_TEST_API_KEY=veil-doppler-test-secret-12345`
2. Configures veil to use Doppler
3. Makes HTTP requests through veil MITM proxy
4. Verifies secrets are fetched from Doppler and injected into headers

### If the test fails:

The test automatically sets the secret in Doppler, but if it fails:

```bash
# Manually set the secret
doppler secrets set VEIL_TEST_API_KEY --value "veil-doppler-test-secret-12345"

# Verify it's set
doppler secrets get VEIL_TEST_API_KEY --plain

# Run the test again
./test_veil_doppler_e2e.sh
```

## Quick Verification

To quickly verify Doppler integration works with your credentials:

```bash
# 1. Run the mock test (no credentials needed)
./test_veil_doppler_mock_e2e.sh

# 2. If mock test passes, try with real Doppler
export DOPPLER_TOKEN="your-token-here"
./test_veil_doppler_e2e.sh
```

## Architecture

Both tests use the same architecture:

```
┌─────────────┐
│   curl      │  Client wrapped by veil
│  (client)   │
└──────┬──────┘
       │
       │ HTTP request
       ▼
┌─────────────────────────────┐
│   Veil MITM Proxy           │
│                             │
│  1. Fetch secret from       │
│     Doppler API ───────────►  Mock/Real Doppler API
│  2. Inject into header      │
│  3. Forward request         │
└──────┬──────────────────────┘
       │
       │ HTTP + Authorization: Bearer <secret>
       ▼
┌─────────────┐
│ Echo Server │  Echoes back request with headers
└─────────────┘
```

## Debugging

If tests fail, check:

1. **Mock test fails**: Python environment issue
   ```bash
   python3 --version  # Should be 3.6+
   ```

2. **Real test fails**: Doppler credentials
   ```bash
   doppler secrets --project veilwarden --config dev_personal
   ```

3. **Port conflicts**: Echo or mock server port in use
   ```bash
   lsof -i :9095  # Echo port
   lsof -i :9097  # Mock Doppler port
   ```

4. **View logs**: Paths shown at end of test
   ```bash
   # Example from test output
   cat /tmp/veil-doppler-echo.XXXX.log
   cat /tmp/veil-doppler-mock.XXXX.log
   ```
