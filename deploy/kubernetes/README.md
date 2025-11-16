# Veilwarden Kubernetes Deployment

This directory contains production-ready Kubernetes manifests for deploying veilwarden as a DaemonSet with workload identity support.

## Architecture

Veilwarden runs as a **DaemonSet** with `hostNetwork: true`, providing a node-local proxy on `localhost:8088`. This allows pods to authenticate using their Kubernetes Service Account tokens and access secrets through the proxy.

## Quick Start

### Prerequisites

- Kubernetes 1.25+ cluster
- kubectl configured
- Doppler token (or another secret backend)
- kustomize (built into kubectl 1.14+)

### 1. Deploy the Manifests

```bash
# Deploy everything with kustomize
kubectl apply -k deploy/kubernetes/

# Or apply individual files
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/serviceaccount.yaml
kubectl apply -f deploy/kubernetes/clusterrole.yaml
kubectl apply -f deploy/kubernetes/clusterrolebinding.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/daemonset.yaml
```

### 2. Create Required Secrets

Before the DaemonSet can start, create the secrets:

```bash
# Create veilwarden-secrets with Doppler token
kubectl create secret generic veilwarden-secrets \
  -n veilwarden \
  --from-literal=session-secret=$(openssl rand -hex 32) \
  --from-literal=doppler-token=$DOPPLER_TOKEN

# Create veilwarden-policies ConfigMap (example)
kubectl create configmap veilwarden-policies \
  -n veilwarden \
  --from-file=policies/kubernetes-example.rego
```

### 3. Verify Deployment

```bash
# Check DaemonSet status
kubectl get daemonset -n veilwarden

# Check pod logs
kubectl logs -n veilwarden -l app=veilwarden

# Verify RBAC permissions
kubectl auth can-i create tokenreviews.authentication.k8s.io \
  --as=system:serviceaccount:veilwarden:veilwarden
```

## Manifest Files

### namespace.yaml
Creates the `veilwarden` namespace for all resources.

### serviceaccount.yaml
Creates the `veilwarden` ServiceAccount that pods use to authenticate to the Kubernetes API.

### clusterrole.yaml
Defines permissions for TokenReview API access (required for validating pod tokens).

**Permissions granted:**
- `authentication.k8s.io/tokenreviews`: `create`

### clusterrolebinding.yaml
Binds the ClusterRole to the veilwarden ServiceAccount.

### configmap.yaml
Contains the veilwarden configuration file (`config.yaml`).

**Default configuration:**
- Kubernetes authentication: `enabled: auto`
- Token validation: `tokenreview` method
- OPA policy engine enabled
- Example GitHub API route

### daemonset.yaml
Deploys veilwarden as a DaemonSet with:
- **hostNetwork: true** - Node-local proxy on localhost:8088
- **ServiceAccount:** veilwarden
- **Volumes:** Config and policy ConfigMaps
- **Health checks:** Liveness and readiness probes on /healthz
- **Resources:** 100m CPU, 128Mi memory (requests), 500m CPU, 256Mi memory (limits)

### kustomization.yaml
Kustomize configuration for managing all resources.

**Features:**
- Sets namespace for all resources
- Manages image tag (default: v0.2.0)
- References all manifest files

## Using from Application Pods

### Method 1: Direct Bearer Token Authentication

```go
package main

import (
    "fmt"
    "io"
    "net/http"
    "os"
)

func main() {
    // Read pod's Service Account token
    token, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")

    req, _ := http.NewRequest("GET", "http://localhost:8088/repos/octocat/Hello-World", nil)
    req.Header.Set("Authorization", "Bearer "+string(token))
    req.Header.Set("X-Upstream-Host", "api.github.com")

    resp, _ := http.DefaultClient.Do(req)
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
}
```

### Method 2: HTTP_PROXY Environment Variable

Configure your pod to use veilwarden as an HTTP proxy:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  namespace: my-namespace
spec:
  containers:
  - name: app
    image: my-app:latest
    env:
    - name: HTTP_PROXY
      value: "http://localhost:8088"
    - name: HTTPS_PROXY
      value: "http://localhost:8088"
```

### Method 3: Test with curl

```bash
# From within a pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -H "Authorization: Bearer $TOKEN" \
     -H "X-Upstream-Host: api.github.com" \
     http://localhost:8088/repos/octocat/Hello-World
```

## Configuration

### Customize the Image Tag

Edit `kustomization.yaml`:

```yaml
images:
- name: veilwarden
  newTag: v0.3.0  # Change to your desired version
```

### Add Custom Routes

Edit `configmap.yaml` to add more upstream routes:

```yaml
data:
  config.yaml: |
    routes:
      - upstream_host: api.github.com
        upstream_scheme: https
        secret_id: GITHUB_TOKEN
        inject_header: Authorization
        header_value_template: "token {{secret}}"

      - upstream_host: api.stripe.com
        upstream_scheme: https
        secret_id: STRIPE_SECRET_KEY
        inject_header: Authorization
        header_value_template: "Bearer {{secret}}"
```

### Add OPA Policies

Create a ConfigMap with your Rego policies:

```bash
kubectl create configmap veilwarden-policies \
  -n veilwarden \
  --from-file=allow-prod.rego \
  --from-file=deny-staging.rego
```

Example policy (allow-prod.rego):

```rego
package veilwarden.authz

# Only production namespace can access Stripe
allow if {
    input.namespace == "production"
    input.upstream_host == "api.stripe.com"
}

# CI/CD pipeline can access GitHub
allow if {
    input.service_account == "github-actions"
    input.upstream_host == "api.github.com"
}
```

## Deployment Patterns

### DaemonSet (Default)
- **Pros:** Node-local proxy, no network hop, high availability
- **Cons:** Higher resource usage (one pod per node)
- **Use case:** Production environments, performance-critical workloads

### Alternative: Deployment with NodePort
If resource usage is a concern, you can convert to a Deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: veilwarden
  namespace: veilwarden
spec:
  replicas: 2
  selector:
    matchLabels:
      app: veilwarden
  template:
    # ... same as DaemonSet but without hostNetwork
```

Then expose via Service:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: veilwarden
  namespace: veilwarden
spec:
  type: ClusterIP
  selector:
    app: veilwarden
  ports:
  - port: 8088
    targetPort: 8088
```

## Security Considerations

### Minimal RBAC
The ClusterRole grants **only** `create` permission on `tokenreviews`. This is the minimum required for validating Service Account tokens.

### Network Policy
Consider adding a NetworkPolicy to restrict which pods can access veilwarden:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: veilwarden-access
  namespace: veilwarden
spec:
  podSelector:
    matchLabels:
      app: veilwarden
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {}  # Allow from all pods in the cluster
```

### Secret Management
The `veilwarden-secrets` Secret contains:
- `session-secret`: For backwards compatibility with static auth
- `doppler-token`: For fetching secrets from Doppler

**Never commit these secrets to version control.** Use a secret management tool like:
- Sealed Secrets
- External Secrets Operator
- Vault
- AWS Secrets Manager

## Troubleshooting

### Pods fail to start

Check if secrets exist:
```bash
kubectl get secret veilwarden-secrets -n veilwarden
kubectl get configmap veilwarden-policies -n veilwarden
```

### Authentication failures

Check RBAC permissions:
```bash
kubectl auth can-i create tokenreviews.authentication.k8s.io \
  --as=system:serviceaccount:veilwarden:veilwarden
```

Check logs:
```bash
kubectl logs -n veilwarden -l app=veilwarden | grep -i "kubernetes authentication"
```

### Policy denials

View policy evaluation logs:
```bash
kubectl logs -n veilwarden -l app=veilwarden | grep -i policy
```

Enable OPA decision logging in `configmap.yaml`:
```yaml
policy:
  enabled: true
  engine: opa
  decision_log: true  # Add this
```

### Port already in use

If `hostPort: 8088` conflicts with another service, change it in `daemonset.yaml`:

```yaml
ports:
- name: proxy
  containerPort: 8088
  hostPort: 8089  # Change to available port
  protocol: TCP
```

## Monitoring

### Metrics
If Prometheus is available, add annotations to the DaemonSet:

```yaml
template:
  metadata:
    annotations:
      prometheus.io/scrape: "true"
      prometheus.io/port: "8088"
      prometheus.io/path: "/metrics"
```

### Logging
Logs are written to stdout and can be collected by your logging solution:

```bash
# View real-time logs
kubectl logs -f -n veilwarden -l app=veilwarden

# Search for authentication events
kubectl logs -n veilwarden -l app=veilwarden | grep "authenticated"

# Search for policy decisions
kubectl logs -n veilwarden -l app=veilwarden | grep "policy"
```

## Uninstallation

```bash
# Remove all resources
kubectl delete -k deploy/kubernetes/

# Or delete namespace (removes everything)
kubectl delete namespace veilwarden
```

## Next Steps

1. Read the complete documentation: `docs/kubernetes-workload-identity.md`
2. Review example policies: `policies/kubernetes-example.rego`
3. See the implementation plan: `docs/kubernetes-implementation-plan.md`

## Support

For issues or questions:
- GitHub Issues: https://github.com/yourusername/veilwarden/issues
- Design doc: `docs/kubernetes-workload-identity.md`
- Implementation plan: `docs/kubernetes-implementation-plan.md`
