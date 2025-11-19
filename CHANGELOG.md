# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-11-19

### Added

#### Laptop MITM Proxy Mode
- **New `veil` CLI** for running commands through transparent MITM proxy
  - `veil init` - Create configuration directory and example files
  - `veil exec` - Execute commands with automatic credential injection
- **Ephemeral CA certificate generation** with 1-hour validity for secure MITM interception
- **Transparent environment variable injection** for HTTP_PROXY, HTTPS_PROXY, and CA certificates
  - Supports Python (requests, httplib2, pip), Node.js, Go, curl, and AWS CLI
- **Session-based isolation** with unique session IDs per invocation
- **MITM proxy using google/martian v3.3.3** with policy enforcement and secret injection
- **Internal proxy package** (`internal/proxy`) for code sharing between server and CLI
- **E2E test suite** (`test_veil_e2e.sh`) for validating laptop mode functionality

#### OPA Integration
- **OPA policy engine** with v1 SDK integration
- **Policy enforcement** with request body inspection and decision logging
- **Complex policy examples** demonstrating agent identity, resource access, and namespace controls
- **Policy engine factory** supporting multiple policy engine types (config-based, OPA)
- **Kubernetes identity integration** with namespace and pod-based access control
- **Configurable OPA settings** in `veilwarden.yaml`:
  - `policy_path` - Directory containing Rego policy files
  - `decision_path` - OPA query path for allow/deny decisions
  - `default_decision` - Fallback decision when policy evaluation fails

#### Kubernetes Support
- **Service account token authentication** with Kubernetes API validation
- **Namespace and pod name injection** into policy context
- **Kubernetes-specific identity attributes** for fine-grained access control
- **Configurable Kubernetes settings** in `veilwarden.yaml`:
  - `enabled` - Toggle Kubernetes authentication
  - `api_server_url` - Kubernetes API server endpoint
  - `verify_ssl` - TLS verification toggle for development

### Changed

- **PolicyInput extended** with `Body` and `SessionID` fields for laptop mode support
- **Header processing logic** improved to remove inbound auth headers before secret injection
- **Route lookup** now happens early to populate `SecretID` in policy context
- **Secret injection** now uses template-based approach with `{{secret}}` placeholder
- **CLI moved to cobra framework** for better command structure and flag management

### Fixed

- **Authorization header handling** - Now correctly removes client auth headers while preserving injected secrets
- **Serial number generation** for CA certificates now uses cryptographically secure random values
- **Session header stripping** prevents leaking VeilWarden-specific headers to upstream APIs

### Security

- **Inbound Authorization header removal** prevents leaking Kubernetes tokens or session secrets to upstream APIs
- **Session-scoped CA certificates** with automatic cleanup after command execution
- **Policy enforcement before secret access** ensures zero-trust security model
- **Request body inspection** allows policies to validate payload content

### Documentation

- Added comprehensive [laptop mode quick start](README.md#option-2-laptop-mode-transparent-mitm-proxy) guide
- Added [OPA integration documentation](docs/OPA_INTEGRATION.md) with policy examples
- Added [implementation plan](docs/plans/2025-11-18-laptop-mitm-proxy-implementation.md) for laptop MITM proxy
- Added [design document](docs/LAPTOP_MITM_DESIGN.md) explaining architecture and security model
- Added [design review](docs/reviews/2025-11-18-mitm-design-review.md) with security analysis
- Added [production readiness checklist](PRODUCTION_READINESS.md)

### Dependencies

- Added `github.com/google/martian/v3 v3.3.3` - MITM proxy framework
- Added `github.com/spf13/cobra v1.8.0` - CLI framework
- Added `github.com/open-policy-agent/opa v1.0.0` - Policy evaluation engine
- Added `gopkg.in/yaml.v3 v3.0.1` - YAML configuration parsing

## [1.0.0] - 2024-11-XX

### Added
- Initial release with sidecar proxy mode
- Doppler secret store integration
- Static identity authentication
- Basic policy enforcement
- HTTP/HTTPS proxy support
- Request ID tracking and logging

[2.0.0]: https://github.com/yourusername/veilwarden/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/yourusername/veilwarden/releases/tag/v1.0.0
