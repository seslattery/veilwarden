# Kubernetes Manifests Summary

**Milestone 5 Implementation - Complete**

This document provides a technical summary of all Kubernetes manifests created for veilwarden's workload identity support.

## Overview

All 7 required Kubernetes manifest files have been created according to the specification in `/Users/sean/dev/veilwarden/docs/kubernetes-implementation-plan.md` (Milestone 5).

## Files Created

### Core Manifests (7 files)

1. **namespace.yaml** (60 bytes)
   - Creates `veilwarden` namespace
   - Isolates all veilwarden resources

2. **serviceaccount.yaml** (89 bytes)
   - ServiceAccount: `veilwarden`
   - Used by DaemonSet pods
   - Bound to ClusterRole for TokenReview API access

3. **clusterrole.yaml** (196 bytes)
   - ClusterRole: `veilwarden-tokenreview`
   - Grants minimal permissions: `create` on `tokenreviews`
   - API Group: `authentication.k8s.io`

4. **clusterrolebinding.yaml** (281 bytes)
   - Binds ClusterRole to ServiceAccount
   - Enables TokenReview API calls

5. **configmap.yaml** (525 bytes)
   - ConfigMap: `veilwarden-config`
   - Contains `config.yaml` with:
     - Example GitHub API route
     - Kubernetes auth: `enabled: auto`
     - OPA policy engine configuration
     - Policy path: `/etc/veilwarden/policies`

6. **daemonset.yaml** (1.9 KB)
   - DaemonSet: `veilwarden`
   - Key features:
     - `hostNetwork: true` (node-local proxy)
     - `hostPort: 8088` (accessible on localhost)
     - ServiceAccount: `veilwarden`
     - Resource limits: 500m CPU, 256Mi memory
     - Health checks: liveness and readiness probes
     - Volumes: config and policies ConfigMaps
     - Secrets: `veilwarden-secrets` (session-secret, doppler-token)

7. **kustomization.yaml** (262 bytes)
   - Kustomize configuration
   - Sets namespace for all resources
   - References all manifest files
   - Image tag: `v0.2.0`

### Documentation (3 files)

1. **README.md** (9.3 KB)
   - Comprehensive deployment documentation
   - Architecture explanation
   - Usage examples (Go, curl, HTTP_PROXY)
   - Configuration guide
   - Troubleshooting section
   - Security considerations

2. **DEPLOYMENT.md** (7.2 KB)
   - Quick deployment guide (<5 minutes)
   - Step-by-step instructions
   - Customization examples
   - Multi-environment patterns
   - Monitoring and cleanup

3. **MANIFEST_SUMMARY.md** (this file)
   - Technical summary of all manifests
   - Validation results
   - Key configurations

### Scripts (1 file)

1. **verify.sh** (3.4 KB, executable)
   - Validates all manifests before deployment
   - Checks for required files
   - Verifies resource types
   - Confirms RBAC and DaemonSet configuration
   - Provides deployment instructions

## Validation Results

All manifests have been validated:

```bash
$ ./deploy/kubernetes/verify.sh
✓ kubectl is installed
✓ Kustomization builds successfully
✓ Found 6 Kubernetes resources
✓ All 7 required files present
✓ All 6 expected resource types found
✓ RBAC configuration correct
✓ DaemonSet configuration correct
✓ ConfigMap configuration correct
```

### Kustomize Build Output

The kustomize build produces 6 Kubernetes resources:

1. Namespace: `veilwarden`
2. ServiceAccount: `veilwarden`
3. ClusterRole: `veilwarden-tokenreview`
4. ClusterRoleBinding: `veilwarden-tokenreview`
5. ConfigMap: `veilwarden-config`
6. DaemonSet: `veilwarden`

## Key Configurations

### RBAC Permissions

**ClusterRole grants:**
- API Group: `authentication.k8s.io`
- Resources: `tokenreviews`
- Verbs: `create`

**Why:** Minimal permission required to validate Service Account tokens via TokenReview API.

### DaemonSet Specifications

**Networking:**
- `hostNetwork: true` - Runs on host network
- `hostPort: 8088` - Accessible on localhost:8088
- Enables node-local proxy pattern

**ServiceAccount:**
- `serviceAccountName: veilwarden`
- Provides identity for TokenReview API calls

**Resources:**
- Requests: 100m CPU, 128Mi memory
- Limits: 500m CPU, 256Mi memory

**Volumes:**
1. `config` - veilwarden-config ConfigMap
   - Mounted at: `/etc/veilwarden`
2. `policies` - veilwarden-policies ConfigMap
   - Mounted at: `/etc/veilwarden/policies`

**Secrets:**
- `veilwarden-secrets` (must be created separately)
  - `session-secret` - For backwards compatibility
  - `doppler-token` - For Doppler integration

**Health Checks:**
- Liveness: `/healthz` every 30s (after 10s initial delay)
- Readiness: `/healthz` every 10s (after 5s initial delay)

### ConfigMap Configuration

**Default routes:**
- GitHub API (api.github.com)
  - Secret: `GITHUB_TOKEN`
  - Header: `Authorization: token {{secret}}`

**Kubernetes authentication:**
- `enabled: auto` - Auto-detect if running in Kubernetes
- `validate_method: tokenreview` - Use TokenReview API

**Policy engine:**
- `enabled: true`
- `engine: opa`
- `policy_path: /etc/veilwarden/policies`
- `decision_path: veilwarden/authz/allow`

## Deployment Architecture

```
┌─────────────────────────────────────────────┐
│           Kubernetes Cluster                │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │         veilwarden Namespace         │  │
│  │                                      │  │
│  │  ┌────────────────────────────────┐ │  │
│  │  │  DaemonSet (one pod per node) │ │  │
│  │  │                                │ │  │
│  │  │  Pod 1 (Node A)                │ │  │
│  │  │  - localhost:8088              │ │  │
│  │  │  - ServiceAccount: veilwarden  │ │  │
│  │  │                                │ │  │
│  │  │  Pod 2 (Node B)                │ │  │
│  │  │  - localhost:8088              │ │  │
│  │  │  - ServiceAccount: veilwarden  │ │  │
│  │  │                                │ │  │
│  │  │  Pod 3 (Node C)                │ │  │
│  │  │  - localhost:8088              │ │  │
│  │  │  - ServiceAccount: veilwarden  │ │  │
│  │  └────────────────────────────────┘ │  │
│  │                                      │  │
│  │  ConfigMaps:                         │  │
│  │  - veilwarden-config                 │  │
│  │  - veilwarden-policies (user-created)│ │
│  │                                      │  │
│  │  Secrets:                            │  │
│  │  - veilwarden-secrets (user-created) │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  RBAC:                                      │
│  - ClusterRole: veilwarden-tokenreview      │
│  - ClusterRoleBinding: veilwarden-tokenreview│
└─────────────────────────────────────────────┘
```

## Usage Flow

1. **Application pod** reads its Service Account token from:
   `/var/run/secrets/kubernetes.io/serviceaccount/token`

2. **Pod makes request** to localhost:8088:
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
        -H "X-Upstream-Host: api.github.com" \
        http://localhost:8088/repos
   ```

3. **Veilwarden validates token** via TokenReview API:
   - Calls Kubernetes API server
   - Verifies token authenticity
   - Extracts namespace, service account, pod name

4. **OPA policy evaluation**:
   - Input includes: namespace, service_account, pod_name
   - Policy decides: allow or deny

5. **Request proxied**:
   - Fetches secret from Doppler
   - Injects into Authorization header
   - Proxies to upstream API

## Pre-Deployment Checklist

Before deploying, ensure:

- [ ] Kubernetes 1.25+ cluster available
- [ ] kubectl configured and working
- [ ] Docker image built and available
- [ ] Doppler token ready (or alternative secret backend)
- [ ] OPA policies written (optional, can add later)

**Required manual steps:**

1. Create `veilwarden-secrets` Secret:
   ```bash
   kubectl create secret generic veilwarden-secrets \
     -n veilwarden \
     --from-literal=session-secret=$(openssl rand -hex 32) \
     --from-literal=doppler-token=$DOPPLER_TOKEN
   ```

2. Create `veilwarden-policies` ConfigMap:
   ```bash
   kubectl create configmap veilwarden-policies \
     -n veilwarden \
     --from-file=policies/
   ```

## Deployment Commands

### Quick Deploy

```bash
# Verify manifests
./deploy/kubernetes/verify.sh

# Deploy
kubectl apply -k deploy/kubernetes/

# Verify
kubectl get all -n veilwarden
```

### Custom Image Tag

Edit `kustomization.yaml`:
```yaml
images:
- name: veilwarden
  newTag: v0.3.0  # Your version
```

Then deploy:
```bash
kubectl apply -k deploy/kubernetes/
```

### Update Configuration

```bash
# Edit config
vim deploy/kubernetes/configmap.yaml

# Apply changes
kubectl apply -f deploy/kubernetes/configmap.yaml

# Restart to pick up changes
kubectl rollout restart daemonset/veilwarden -n veilwarden
```

## Verification Commands

```bash
# Check all resources
kubectl get all -n veilwarden

# Check RBAC
kubectl auth can-i create tokenreviews.authentication.k8s.io \
  --as=system:serviceaccount:veilwarden:veilwarden

# Check logs
kubectl logs -n veilwarden -l app=veilwarden --tail=50

# Test from pod
kubectl run test --rm -it --image=curlimages/curl -- sh
# Then inside pod:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -H "Authorization: Bearer $TOKEN" \
     -H "X-Upstream-Host: httpbin.org" \
     http://localhost:8088/headers
```

## Integration with Implementation Plan

This completes **Milestone 5** from the Kubernetes implementation plan:

| Milestone | Status | Location |
|-----------|--------|----------|
| M1: Core Token Validation | Pending | `cmd/veilwarden/k8s_*.go` |
| M2: Unit Tests | Pending | `cmd/veilwarden/*_test.go` |
| M3: Integration Tests | Pending | `cmd/veilwarden/integration_k8s_test.go` |
| M4: E2E Tests | Pending | `cmd/veilwarden/e2e_k8s_test.go` |
| **M5: Deployment Manifests** | **✅ Complete** | `deploy/kubernetes/` |
| M6: Documentation | Pending | `docs/`, `README.md` |

**Files required for M5:** ✅ All created
- [x] namespace.yaml
- [x] serviceaccount.yaml
- [x] clusterrole.yaml
- [x] clusterrolebinding.yaml
- [x] configmap.yaml
- [x] daemonset.yaml
- [x] kustomization.yaml

**Bonus files created:**
- [x] README.md (comprehensive guide)
- [x] DEPLOYMENT.md (quick start)
- [x] verify.sh (validation script)
- [x] MANIFEST_SUMMARY.md (this file)

## Next Steps

1. Implement Milestone 1-4 (code implementation and tests)
2. Build Docker image
3. Test deployment in kind cluster
4. Update main README.md (Milestone 6)
5. Create policy examples
6. Production deployment

## Related Documentation

- Implementation Plan: `/Users/sean/dev/veilwarden/docs/kubernetes-implementation-plan.md`
- Design Document: `/Users/sean/dev/veilwarden/docs/kubernetes-workload-identity.md`
- Deployment Guide: `/Users/sean/dev/veilwarden/deploy/kubernetes/DEPLOYMENT.md`
- Full README: `/Users/sean/dev/veilwarden/deploy/kubernetes/README.md`

## Support

For issues or questions:
- Review the documentation in `deploy/kubernetes/README.md`
- Check the implementation plan
- File GitHub issues

---

**Implementation Date:** 2025-11-16
**Implemented By:** Claude
**Milestone:** 5 (Deployment Manifests)
**Status:** ✅ Complete
