# Codebase Review: Veilwarden
**Date:** 2025-11-20
**Reviewer:** Antigravity

## Executive Summary

Veilwarden is a well-structured Go application designed to act as a secure egress proxy for AI agents and services. It effectively leverages existing tools like `google/martian` for proxying, Open Policy Agent (OPA) for authorization, and Doppler for secret management. The codebase is clean, modular, and includes good observability practices with OpenTelemetry.

However, there are some potential security and performance considerations, particularly regarding how request bodies are handled for policy evaluation and the simplicity of the current secret injection mechanism.

## 1. Architecture & Design

### Strengths
*   **Modular Design:** The separation between `cmd/veilwarden` (server), `cmd/veil` (CLI), and `internal` packages (`proxy`, `policy`, `doppler`) is logical and promotes maintainability.
*   **Extensibility:** The use of interfaces for `SecretStore` and `PolicyEngine` allows for easy addition of new backends (e.g., Vault, AWS Secrets Manager).
*   **Observability:** Native integration with OpenTelemetry (OTEL) for tracing and metrics is excellent for production readiness.
*   **K8s Native:** The "auto" detection for Kubernetes environments and use of Service Account tokens for authentication aligns well with cloud-native best practices.

### Weaknesses
*   **Proxy Fidelity:** The manual header copying and stripping in `cmd/veilwarden/server.go` (specifically `copyHeaders` and `hopHeaders`) might miss some edge cases or standard proxy behaviors compared to using a dedicated proxy library's full capabilities. While `martian` is used in the CLI, the server implementation seems to roll its own request forwarding logic in `handleHTTP`.
*   **Configuration Evolution:** The current `veilwarden.yaml` is simple, but as requirements grow (e.g., regex-based path matching, complex header transformations), it may become limiting.

## 2. Security Review

### Strengths
*   **Ephemeral CA:** The CLI generates a per-session ephemeral CA for MITM, reducing the risk of long-lived CA key compromise.
*   **Secret Isolation:** Secrets are injected at the proxy layer and stripped from the child process environment (specifically `DOPPLER_TOKEN`), preventing accidental leakage.
*   **Policy Enforcement:** OPA integration allows for fine-grained access control.

### Risks & Vulnerabilities
*   **Request Body Buffering (DoS Risk):** In `internal/proxy/martian.go`, the `policyModifier` reads the entire request body into memory (`io.ReadAll`) to pass to OPA.
    *   **Risk:** A malicious agent or compromised service could send a massive request body, causing the proxy to run out of memory (OOM) and crash (Denial of Service).
    *   **Recommendation:** Implement a strict limit on the size of the request body read for policy evaluation (e.g., `io.LimitReader`). If the body exceeds the limit, either truncate it (if policy allows) or reject the request.
*   **Session Secret:** The local mode uses a single `X-Session-Secret`. If this secret is leaked (e.g., via process listing or logs), an attacker on the local machine could bypass auth.
    *   **Recommendation:** Ensure the secret is passed via a secure channel or file descriptor if possible, though environment variable is acceptable for local dev if the machine is trusted.
*   **Header Injection:** Secret injection uses `strings.ReplaceAll`. While generally safe for headers, it doesn't handle encoding or escaping.
    *   **Risk:** If a secret contains characters that are invalid in HTTP headers (e.g., newlines), it could break the request or lead to header injection attacks if the secret value is user-controlled (unlikely for secrets, but possible).
    *   **Recommendation:** Validate secret values before injection to ensure they conform to HTTP header field value standards.

## 3. Implementation Details

### `cmd/veilwarden` (Server)
*   **`server.go`**: The `handleHTTP` function manually constructs upstream requests. It removes `Authorization` headers to prevent leaking the K8s token, which is correct.
*   **`k8s_auth.go`**: Uses `TokenReview` API. This is the standard way to validate K8s tokens.

### `cmd/veil` (CLI)
*   **`exec.go`**: Sets up the environment correctly. Strips `DOPPLER_TOKEN`.
*   **`mitm`**: Uses `martian` for the local proxy. This is a robust choice.

### `internal/proxy`
*   **`martian.go`**: The `policyModifier` and `secretInjectorModifier` are well-implemented, aside from the body reading issue mentioned above.

### `internal/doppler`
*   **`store.go`**: Caches secrets with a TTL. Thread-safe using `sync.Mutex`. Implementation looks solid.

## 4. Recommendations

### High Priority
1.  **Limit Request Body Size:** Modify `internal/proxy/martian.go` (and `cmd/veilwarden/server.go` if applicable) to use `io.LimitReader` when reading the request body for OPA.
2.  **Validate Secrets:** Add a check to ensure fetched secrets do not contain invalid header characters (e.g., `\r`, `\n`).

### Medium Priority
1.  **Unify Proxy Logic:** The server (`cmd/veilwarden`) and CLI (`cmd/veil`) seem to use slightly different proxying approaches (`net/http` reverse proxy logic vs `martian`). Consider unifying them to use `martian` everywhere for consistency and feature parity.
2.  **Enhanced Policy Input:** Add more context to the OPA input, such as the client IP address or TLS fingerprint (if applicable).

### Low Priority
1.  **Config Validation:** Add stricter validation for `veilwarden.yaml` at startup, perhaps using a schema validator.
2.  **Structured Logging:** Ensure all logs are structured (JSON) in production for easier parsing.

## 5. Conclusion

Veilwarden is in a good state for an "Experimental MVP". The core security concepts are sound. Addressing the request body buffering issue is the most critical next step to ensure stability.
