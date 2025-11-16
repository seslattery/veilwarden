# End-to-End Testing Guide

This document describes how to run end-to-end (E2E) tests for veilwarden's Kubernetes integration.

## Overview

The E2E test suite validates the complete Kubernetes Workload Identity integration by:
1. Creating a real kind cluster
2. Building and deploying veilwarden as a DaemonSet
3. Creating test ServiceAccounts with tokens
4. Making authenticated requests using Kubernetes tokens
5. Verifying the full authentication flow

## Prerequisites

Install the required tools:

```bash
# Install kind (Kubernetes in Docker)
go install sigs.k8s.io/kind@latest

# Install kubectl
# On macOS:
brew install kubectl

# On Linux:
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Verify Docker is running
docker ps
```

## Running E2E Tests

### Option 1: Automated Script (Recommended)

Run the complete E2E test suite with a single command:

```bash
./scripts/test_k8s_e2e.sh
```

This script will:
- Create a kind cluster named `veilwarden-test`
- Build the veilwarden Docker image
- Load the image into kind
- Deploy all Kubernetes manifests
- Create test secrets and policies
- Wait for the DaemonSet to be ready
- Run the E2E tests
- Clean up the cluster on exit

### Option 2: Manual Testing

For debugging or step-by-step testing:

```bash
# 1. Create kind cluster
kind create cluster --name veilwarden-test

# 2. Set KUBECONFIG
export KUBECONFIG="$(kind get kubeconfig --name veilwarden-test)"

# 3. Build Docker image
docker build -t veilwarden:test .

# 4. Load image into kind
kind load docker-image veilwarden:test --name veilwarden-test

# 5. Create test secrets
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: veilwarden-secrets
  namespace: veilwarden
type: Opaque
stringData:
  session-secret: "test-session-secret"
  doppler-token: "test-doppler-token"
EOF

# 6. Create test policies
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: veilwarden-policies
  namespace: veilwarden
data:
  policy.rego: |
    package veilwarden.authz
    allow = true
EOF

# 7. Deploy veilwarden
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/serviceaccount.yaml
kubectl apply -f deploy/kubernetes/clusterrole.yaml
kubectl apply -f deploy/kubernetes/clusterrolebinding.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/daemonset.yaml

# Update image
kubectl set image daemonset/veilwarden veilwarden=veilwarden:test -n veilwarden

# 8. Wait for deployment
kubectl rollout status daemonset/veilwarden -n veilwarden --timeout=5m

# 9. Run E2E tests
cd cmd/veilwarden
go test -v -tags=e2e -timeout=10m

# 10. Clean up
kind delete cluster --name veilwarden-test
```

## E2E Test Details

The E2E test file (`cmd/veilwarden/e2e_k8s_test.go`) includes the following tests:

### TestE2EKubernetesWorkloadIdentity

Tests the complete authentication flow:
1. Creates a test namespace `veilwarden-e2e`
2. Creates a test ServiceAccount `test-workload`
3. Creates RBAC resources (ClusterRole and ClusterRoleBinding)
4. Retrieves the ServiceAccount token from Kubernetes secrets
5. Makes an authenticated request to the veilwarden proxy using the token
6. Verifies the request succeeds with a 200 status

### TestE2EKubernetesInvalidToken

Tests that invalid tokens are properly rejected:
1. Makes a request with an invalid Bearer token
2. Verifies the request is rejected (non-200 status)

## Environment Variables

The E2E tests support the following environment variables:

- `KUBECONFIG`: Path to kubeconfig file (required, tests skip if not set)
- `VEILWARDEN_URL`: URL of the veilwarden proxy (default: `http://localhost:8088`)

## Build Tags

The E2E tests use the `e2e` build tag to prevent them from running during normal test execution:

```bash
# Run only E2E tests
go test -tags=e2e ./cmd/veilwarden

# Run all tests except E2E
go test ./cmd/veilwarden

# Run all tests including E2E
go test -tags=e2e ./...
```

## Troubleshooting

### kind cluster creation fails

```bash
# Clean up any existing clusters
kind delete cluster --name veilwarden-test

# Check Docker is running
docker ps

# Try creating cluster again
kind create cluster --name veilwarden-test
```

### Image not found in kind

```bash
# Verify image was built
docker images | grep veilwarden

# Load image into kind again
kind load docker-image veilwarden:test --name veilwarden-test
```

### DaemonSet not ready

```bash
# Check pod status
kubectl get pods -n veilwarden

# Check pod logs
kubectl logs -n veilwarden -l app=veilwarden

# Describe pod for events
kubectl describe pod -n veilwarden -l app=veilwarden
```

### E2E tests fail with connection refused

```bash
# Verify veilwarden is running
kubectl get pods -n veilwarden

# Check if using hostNetwork
kubectl get daemonset veilwarden -n veilwarden -o yaml | grep hostNetwork

# Test connectivity from within cluster
kubectl run test-pod --rm -it --image=curlimages/curl -- sh
curl http://localhost:8088/healthz
```

### ServiceAccount has no secrets

In Kubernetes 1.24+, ServiceAccount tokens are no longer automatically created. The test handles this, but if you see this error:

```bash
# Manually create token secret
kubectl create token test-workload -n veilwarden-e2e
```

## CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: E2E Tests

on: [push, pull_request]

jobs:
  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.22'

      - name: Install kind
        run: |
          go install sigs.k8s.io/kind@latest

      - name: Run E2E tests
        run: ./scripts/test_k8s_e2e.sh
```

## Next Steps

After E2E tests pass:
1. Review test logs for any warnings
2. Test with production-like policies
3. Test with real secret backends (e.g., Doppler)
4. Test with multiple namespaces and ServiceAccounts
5. Test policy-based access control scenarios

## Related Documentation

- Implementation Plan: `docs/kubernetes-implementation-plan.md`
- Design Document: `docs/kubernetes-workload-identity.md`
- Deployment Guide: `deploy/kubernetes/README.md`
