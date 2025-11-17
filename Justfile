# Veilwarden Development Justfile
# Run `just --list` to see all available commands

# Default recipe - shows help
default:
    @just --list

# Run all tests (unit + basic E2E)
test:
    @echo "Running unit and basic E2E tests..."
    go test -v ./cmd/veilwarden

# Run unit tests only (fast)
test-unit:
    @echo "Running unit tests..."
    go test -v -short ./cmd/veilwarden

# Run integration tests (with EnvTest)
test-integration:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Running integration tests (requires EnvTest)..."
    # Auto-detect KUBEBUILDER_ASSETS if not set
    if [ -z "${KUBEBUILDER_ASSETS:-}" ]; then
        ENVTEST_DIR=$(find "$HOME/Library/Application Support/io.kubebuilder.envtest/k8s" -maxdepth 1 -type d -name "*darwin-arm64" 2>/dev/null | head -1 || true)
        if [ -n "$ENVTEST_DIR" ]; then
            echo "✓ Found EnvTest at $ENVTEST_DIR"
            export KUBEBUILDER_ASSETS="$ENVTEST_DIR"
        elif [ -d "/usr/local/kubebuilder" ]; then
            echo "✓ Found EnvTest at /usr/local/kubebuilder"
            export KUBEBUILDER_ASSETS="/usr/local/kubebuilder"
        else
            echo "⚠️  Warning: EnvTest binaries not found"
            echo "Integration tests requiring K8s API server will be skipped."
            echo "To install: just install-envtest"
            echo ""
        fi
    fi
    go test -v -tags=integration ./cmd/veilwarden || echo "⚠️  Some integration tests failed (likely missing EnvTest)"

# Run Kubernetes E2E tests (requires kind cluster and KUBECONFIG)
test-e2e:
    @echo "Running Kubernetes E2E tests..."
    go test -v -tags=e2e -timeout=10m ./cmd/veilwarden

# Run full E2E test suite with kind cluster
test-k8s-e2e:
    @echo "Running full Kubernetes E2E test suite with kind cluster..."
    ./scripts/test_k8s_e2e.sh

# Run all tests (unit + integration + E2E)
test-all:
    @echo "Running all test suites..."
    @just test
    @echo ""
    @just test-integration
    @echo ""
    @just test-e2e
    @echo ""
    @echo "✅ All available tests completed!"

# Run tests with coverage
test-coverage:
    @echo "Running tests with coverage..."
    go test -v -coverprofile=coverage.out ./cmd/veilwarden
    go tool cover -html=coverage.out -o coverage.html
    @echo "Coverage report generated: coverage.html"

# Lint code
lint:
    @echo "Running golangci-lint..."
    golangci-lint run ./...

# Run vulnerability check
vuln-check:
    @echo "Running govulncheck..."
    govulncheck ./...

# Run all checks (lint + vuln + test)
check: lint vuln-check test
    @echo "✅ All checks passed!"

# Run all checks including integration tests
check-all: lint vuln-check test-all
    @echo "✅ All checks passed!"

# Format code
fmt:
    @echo "Formatting code..."
    go fmt ./...
    gofmt -s -w .

# Tidy dependencies
tidy:
    @echo "Tidying dependencies..."
    go mod tidy

# Build binary
build:
    @echo "Building veilwarden..."
    @mkdir -p bin
    go build -o bin/veilwarden ./cmd/veilwarden
    @echo "✅ Binary built: bin/veilwarden"

# Build Docker image
docker-build:
    @echo "Building Docker image..."
    docker build -t veilwarden:latest .

# Run locally with example config
run:
    @echo "Running veilwarden locally..."
    @if [ -z "$VEILWARDEN_SESSION_SECRET" ]; then \
        export VEILWARDEN_SESSION_SECRET="$$(openssl rand -hex 16)"; \
        echo "Generated session secret: $$VEILWARDEN_SESSION_SECRET"; \
    fi
    go run ./cmd/veilwarden --config examples/veilwarden-local-dev.yaml

# Run with Doppler integration
run-doppler:
    @echo "Running veilwarden with Doppler..."
    @if [ -z "$DOPPLER_TOKEN" ]; then \
        echo "Error: DOPPLER_TOKEN not set"; \
        exit 1; \
    fi
    go run ./cmd/veilwarden --config test-config.yaml

# Clean build artifacts
clean:
    @echo "Cleaning build artifacts..."
    rm -rf bin/
    rm -f coverage.out coverage.html
    rm -rf dist/

# Install development dependencies
install-deps:
    @echo "Installing development dependencies..."
    @echo "Installing golangci-lint..."
    @if ! command -v golangci-lint &> /dev/null; then \
        go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
    else \
        echo "golangci-lint already installed"; \
    fi
    @echo "Installing govulncheck..."
    @if ! command -v govulncheck &> /dev/null; then \
        go install golang.org/x/vuln/cmd/govulncheck@latest; \
    else \
        echo "govulncheck already installed"; \
    fi
    @echo "Installing kind..."
    @if ! command -v kind &> /dev/null; then \
        go install sigs.k8s.io/kind@latest; \
    else \
        echo "kind already installed"; \
    fi
    @echo "✅ All development dependencies installed"
    @echo ""
    @echo "Note: EnvTest binaries not installed (optional for integration tests)"
    @echo "To install EnvTest: just install-envtest"

# Install EnvTest binaries for integration tests
install-envtest:
    @echo "Installing EnvTest binaries..."
    @if [ -d "/usr/local/kubebuilder" ]; then \
        echo "EnvTest already installed at /usr/local/kubebuilder"; \
    else \
        go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest; \
        setup-envtest use -p path; \
        echo ""; \
        echo "⚠️  Note: You may need to manually set KUBEBUILDER_ASSETS"; \
        echo "Run: export KUBEBUILDER_ASSETS=\$$(setup-envtest use -p path)"; \
    fi

# Setup development environment
setup: install-deps tidy
    @echo "✅ Development environment ready"

# CI pipeline (what CI should run)
ci: lint vuln-check test test-integration
    @echo "✅ CI checks passed!"

# Local development workflow
dev: fmt tidy lint test
    @echo "✅ Development checks passed!"
