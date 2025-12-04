# Veilwarden Development Justfile
# Run `just --list` to see all available commands

# Default recipe - shows help
default:
    @just --list

# Run all tests
test:
    @echo "Running all tests..."
    go test -v ./...

# Run unit tests only (fast)
test-unit:
    @echo "Running unit tests..."
    go test -v -short ./...

# Run veil CLI tests
test-veil:
    @echo "Running veil CLI tests..."
    go test -v ./cmd/veil/...

# Run sandbox e2e tests (requires DOPPLER_TOKEN and srt)
test-e2e:
    @echo "Running sandbox E2E tests..."
    go test -v -run TestE2ESandbox ./cmd/veil/...

# Run tests with coverage
test-coverage:
    @echo "Running tests with coverage..."
    go test -v -coverprofile=coverage.out ./...
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

# Format code
fmt:
    @echo "Formatting code..."
    go fmt ./...
    gofmt -s -w .

# Tidy dependencies
tidy:
    @echo "Tidying dependencies..."
    go mod tidy

# Build veil CLI
build:
    @echo "Building veil..."
    @mkdir -p bin
    go build -o bin/veil ./cmd/veil
    @echo "✅ Binary built: bin/veil"

# Build echo server (for testing)
build-echo:
    @echo "Building echo server..."
    @mkdir -p bin
    go build -o bin/echo ./cmd/echo
    @echo "✅ Binary built: bin/echo"

# Build all binaries
build-all: build build-echo
    @echo "✅ All binaries built"

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
    @echo "✅ All development dependencies installed"

# Setup development environment
setup: install-deps tidy
    @echo "✅ Development environment ready"

# CI pipeline (what CI should run)
ci: lint vuln-check test
    @echo "✅ CI checks passed!"

# Local development workflow
dev: fmt tidy lint test
    @echo "✅ Development checks passed!"
