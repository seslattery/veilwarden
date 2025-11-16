#!/usr/bin/env bash
set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
CLUSTER_NAME="veilwarden-test"
NAMESPACE="veilwarden"
IMAGE_NAME="veilwarden:test"

echo -e "${GREEN}Starting Kubernetes E2E Test Suite${NC}"
echo "=========================================="

# Check prerequisites
echo -e "\n${YELLOW}Checking prerequisites...${NC}"
if ! command -v kind &> /dev/null; then
    echo -e "${RED}ERROR: kind not found. Install with: go install sigs.k8s.io/kind@latest${NC}"
    exit 1
fi

if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}ERROR: kubectl not found. Please install kubectl${NC}"
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo -e "${RED}ERROR: docker not found. Please install docker${NC}"
    exit 1
fi

echo -e "${GREEN}✓ All prerequisites found${NC}"

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        echo "Deleting kind cluster: ${CLUSTER_NAME}"
        kind delete cluster --name "${CLUSTER_NAME}" || true
    fi
}

# Register cleanup on exit
trap cleanup EXIT

# Create kind cluster
echo -e "\n${YELLOW}Creating kind cluster...${NC}"
if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
    echo "Cluster ${CLUSTER_NAME} already exists, deleting..."
    kind delete cluster --name "${CLUSTER_NAME}"
fi

kind create cluster --name "${CLUSTER_NAME}" --wait 5m

# Set KUBECONFIG
export KUBECONFIG="$(kind get kubeconfig-path --name "${CLUSTER_NAME}" 2>/dev/null || kind get kubeconfig --name "${CLUSTER_NAME}" | grep -v "^apiVersion:" | head -1)"
if [ -z "$KUBECONFIG" ]; then
    # For newer kind versions
    kind export kubeconfig --name "${CLUSTER_NAME}"
    export KUBECONFIG="${HOME}/.kube/config"
fi

echo -e "${GREEN}✓ Kind cluster created${NC}"

# Verify cluster is ready
echo -e "\n${YELLOW}Verifying cluster is ready...${NC}"
kubectl cluster-info
kubectl get nodes

# Build veilwarden image
echo -e "\n${YELLOW}Building veilwarden Docker image...${NC}"
docker build -t "${IMAGE_NAME}" .

echo -e "${GREEN}✓ Docker image built${NC}"

# Load image into kind
echo -e "\n${YELLOW}Loading image into kind cluster...${NC}"
kind load docker-image "${IMAGE_NAME}" --name "${CLUSTER_NAME}"

echo -e "${GREEN}✓ Image loaded into kind${NC}"

# Create test secrets (not committed to repo)
echo -e "\n${YELLOW}Creating test secrets...${NC}"
cat > /tmp/veilwarden-secrets.yaml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: veilwarden-secrets
  namespace: ${NAMESPACE}
type: Opaque
stringData:
  session-secret: "test-session-secret-for-e2e"
  doppler-token: "test-doppler-token"
EOF

# Create test policy ConfigMap
cat > /tmp/veilwarden-policies.yaml <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: veilwarden-policies
  namespace: ${NAMESPACE}
data:
  policy.rego: |
    package veilwarden.authz

    # Allow all for testing
    allow = true
EOF

# Deploy veilwarden
echo -e "\n${YELLOW}Deploying veilwarden to cluster...${NC}"
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/serviceaccount.yaml
kubectl apply -f deploy/kubernetes/clusterrole.yaml
kubectl apply -f deploy/kubernetes/clusterrolebinding.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f /tmp/veilwarden-secrets.yaml
kubectl apply -f /tmp/veilwarden-policies.yaml

# Update daemonset image to use test image
kubectl apply -f deploy/kubernetes/daemonset.yaml
kubectl set image daemonset/veilwarden veilwarden="${IMAGE_NAME}" -n ${NAMESPACE}

echo -e "${GREEN}✓ Manifests applied${NC}"

# Wait for deployment to be ready
echo -e "\n${YELLOW}Waiting for DaemonSet to be ready...${NC}"
kubectl rollout status daemonset/veilwarden -n ${NAMESPACE} --timeout=5m

echo -e "${GREEN}✓ DaemonSet is ready${NC}"

# Show pod status
echo -e "\n${YELLOW}Pod status:${NC}"
kubectl get pods -n ${NAMESPACE}

# Show veilwarden logs (last 20 lines)
echo -e "\n${YELLOW}Veilwarden logs:${NC}"
kubectl logs -n ${NAMESPACE} -l app=veilwarden --tail=20 || true

# Run E2E tests
echo -e "\n${YELLOW}Running E2E tests...${NC}"
export VEILWARDEN_URL="http://localhost:8088"

# Build and run tests with e2e tag
cd cmd/veilwarden
go test -v -tags=e2e -timeout=10m

echo -e "\n${GREEN}=========================================="
echo -e "E2E Test Suite Completed Successfully!${NC}"
echo -e "${GREEN}==========================================${NC}"
