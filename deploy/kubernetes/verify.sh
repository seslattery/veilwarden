#!/usr/bin/env bash
# verify.sh - Verify Kubernetes manifests before deployment

set -euo pipefail

echo "Verifying Veilwarden Kubernetes manifests..."
echo

# Check if kubectl is installed
if ! command -v kubectl &> /dev/null; then
    echo "ERROR: kubectl is not installed"
    exit 1
fi

echo "✓ kubectl is installed"

# Verify kustomize build works
echo "Building kustomization..."
if kubectl kustomize deploy/kubernetes/ > /dev/null 2>&1; then
    echo "✓ Kustomization builds successfully"
else
    echo "ERROR: Kustomization build failed"
    exit 1
fi

# Count resources
RESOURCE_COUNT=$(kubectl kustomize deploy/kubernetes/ | grep -c "^kind:" || true)
echo "✓ Found $RESOURCE_COUNT Kubernetes resources"

# Verify expected resources exist
echo
echo "Checking for required files:"
FILES=(
    "namespace.yaml"
    "serviceaccount.yaml"
    "clusterrole.yaml"
    "clusterrolebinding.yaml"
    "configmap.yaml"
    "daemonset.yaml"
    "kustomization.yaml"
)

for file in "${FILES[@]}"; do
    if [[ -f "deploy/kubernetes/$file" ]]; then
        echo "  ✓ $file"
    else
        echo "  ✗ $file (MISSING)"
        exit 1
    fi
done

# Verify resource types in kustomization output
echo
echo "Verifying resource types:"
EXPECTED_KINDS=(
    "Namespace"
    "ServiceAccount"
    "ClusterRole"
    "ClusterRoleBinding"
    "ConfigMap"
    "DaemonSet"
)

for kind in "${EXPECTED_KINDS[@]}"; do
    if kubectl kustomize deploy/kubernetes/ | grep -q "^kind: $kind$"; then
        echo "  ✓ $kind"
    else
        echo "  ✗ $kind (MISSING)"
        exit 1
    fi
done

# Verify RBAC configuration
echo
echo "Verifying RBAC configuration:"
if kubectl kustomize deploy/kubernetes/ | grep -q "apiGroups:"; then
    echo "  ✓ ClusterRole has apiGroups"
fi
if kubectl kustomize deploy/kubernetes/ | grep -q "authentication.k8s.io"; then
    echo "  ✓ ClusterRole grants authentication.k8s.io access"
fi
if kubectl kustomize deploy/kubernetes/ | grep -q "tokenreviews"; then
    echo "  ✓ ClusterRole grants tokenreviews permission"
fi

# Verify DaemonSet configuration
echo
echo "Verifying DaemonSet configuration:"
if kubectl kustomize deploy/kubernetes/ | grep -q "hostNetwork: true"; then
    echo "  ✓ DaemonSet uses hostNetwork"
fi
if kubectl kustomize deploy/kubernetes/ | grep -q "serviceAccountName: veilwarden"; then
    echo "  ✓ DaemonSet uses veilwarden ServiceAccount"
fi
if kubectl kustomize deploy/kubernetes/ | grep -q "hostPort: 8088"; then
    echo "  ✓ DaemonSet exposes port 8088"
fi

# Verify ConfigMap has required configuration
echo
echo "Verifying ConfigMap configuration:"
if kubectl kustomize deploy/kubernetes/ | grep -q "config.yaml:"; then
    echo "  ✓ ConfigMap contains config.yaml"
fi
if kubectl kustomize deploy/kubernetes/ | grep -q "enabled: auto"; then
    echo "  ✓ Kubernetes authentication enabled"
fi
if kubectl kustomize deploy/kubernetes/ | grep -q "engine: opa"; then
    echo "  ✓ OPA policy engine configured"
fi

echo
echo "============================================"
echo "All verification checks passed!"
echo "============================================"
echo
echo "To deploy to your cluster, run:"
echo "  kubectl apply -k deploy/kubernetes/"
echo
echo "Before deploying, ensure you have created:"
echo "  1. veilwarden-secrets Secret with doppler-token and session-secret"
echo "  2. veilwarden-policies ConfigMap with your Rego policies"
echo
echo "See deploy/kubernetes/README.md for detailed instructions."
