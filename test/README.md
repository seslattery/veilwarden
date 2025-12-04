# VeilWarden Test Suite

## Unit Tests

```bash
# Run all unit tests
go test ./... -v

# Run specific package
go test ./cmd/veil/sandbox -v
```

## Integration Tests

### Sandbox Integration Test

**Requires:** `anthropic-sandbox` CLI installed

```bash
./test/sandbox_integration_test.sh
```

**What it tests:**
- Filesystem isolation (cannot read ~/.ssh/id_rsa)
- Mount accessibility (can read/write /workspace)
- Proxy environment (HTTP_PROXY set correctly)
- File persistence (files survive sandbox exit)

**CI:** Test runs in CI if `anthropic-sandbox` is available, otherwise skips.

### Complete E2E Integration Test (Doppler + OPA + Sandbox)

**Requires:**
- `DOPPLER_TOKEN` environment variable set to a valid Doppler token
- `anthropic-sandbox` CLI installed
- `opa` CLI installed
- Real Doppler project with secrets configured

```bash
export DOPPLER_TOKEN=dp.st.dev.xxxxx
./test/test_veil_doppler_opa_sandbox_e2e.sh
```

**What it tests:**
- **Real Doppler Integration:** Fetches secrets from Doppler API (no mocks)
- **OPA Policy Enforcement:** Tests allow/deny decisions with real policies
- **Anthropic Sandbox:** Full process and filesystem isolation
- **MITM Proxy:** Request interception and secret injection
- **Complete Integration:** All components working together

**Test scenarios:**
1. Allowed GET request - verifies OPA allows, Doppler fetches secret, proxy injects header
2. Denied GET request - verifies OPA blocks request before secret access
3. Filesystem isolation - verifies sandbox blocks sensitive paths
4. File persistence - verifies mounted directories persist changes
5. Proxy environment - verifies sandbox inherits proxy configuration

**CI:** Skipped in CI (requires real Doppler token and secrets configured).
