# Design Review: Laptop MITM Proxy

**Date**: 2025-11-18
**Subject**: [Laptop MITM Proxy Design](../plans/2025-11-18-laptop-mitm-proxy-design.md)

## Executive Summary

The proposed design for the Laptop MITM Proxy is **sound and well-aligned** with the existing VeilWarden architecture. It effectively leverages the core abstractions (`PolicyEngine`, `secretStore`) while introducing a new operation mode (CLI-based MITM proxy) to support local AI agent development.

## Architecture Fit

### Reuse of Core Components
The design correctly identifies and reuses the following existing components from `cmd/veilwarden/`:
- **`PolicyEngine`**: The interface in `policy.go` is generic enough to support the new `PolicyInput` fields (Body, SessionID) without breaking changes.
- **`secretStore`**: The `doppler_store.go` implementation can be reused directly.
- **`config.go`**: The YAML structure for routes is compatible.

### New Components
The separation of the CLI (`cmd/veil`) from the server (`cmd/veilwarden`) is a good decision. It keeps the heavy K8s dependencies out of the local CLI tool where possible, though they share the same repo.

## Dependency Analysis

### `github.com/google/martian/v3`
- **Status**: This library is **archived** by Google and read-only.
- **Risk**: High. While stable, it will not receive security updates.
- **Recommendation**: Consider using a maintained fork or an alternative like `elazarl/goproxy` if long-term maintenance is a concern. However, for an internal developer tool, `martian`'s feature set (specifically the modifier architecture) fits the requirements very well.

### `sandbox-runtime`
- The design mentions integration with `anthropic/sandbox-runtime` but does not detail the Go bindings or integration points. This is a complexity risk during implementation.

## Codebase Impact

### Required Changes
1.  **`go.mod`**: Add `github.com/google/martian/v3`.
2.  **`cmd/veilwarden/policy.go`**:
    - Update `PolicyInput` struct to include `Body`, `SessionID`, `AgentID` (already in code but maybe needs alignment).
    - The design adds `Body` string to `PolicyInput`. This is necessary for the "block expensive reasoning models" policy example.
3.  **`cmd/veilwarden/martian_*.go`**: New files to implement the proxy logic.

### Refactoring Opportunities
- The `PolicyEngine` and `secretStore` interfaces are currently inside `cmd/veilwarden/`. To share them cleanly with `cmd/veil/`, they should ideally be moved to a shared internal package (e.g., `internal/authz`, `internal/secrets`).
- **Current**: `cmd/veilwarden/policy.go`
- **Proposed**: `internal/policy/engine.go`
- This prevents `cmd/veil` from importing `cmd/veilwarden`, which is generally bad practice in Go.

## Security Considerations

1.  **Ephemeral CA**: The design correctly limits the CA validity to 1 hour and stores it in `os.TempDir()`.
2.  **Credential Injection**: The design relies on `martian` modifiers to inject headers. This is secure as long as the proxy itself is not exposed externally (it binds to `127.0.0.1` by default).
3.  **OPA Policies**: The addition of request body inspection allows for fine-grained control (e.g., model allowlists), which is a significant security upgrade for local development.

## Conclusion

**Approved with minor suggestions**:
1.  Plan to refactor shared interfaces (`PolicyEngine`, `secretStore`) into `internal/` packages to avoid import cycles or bad dependency graphs.
2.  Verify `martian` suitability given its archived status.
