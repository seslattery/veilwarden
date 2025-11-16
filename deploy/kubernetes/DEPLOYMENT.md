# Quick Deployment Guide

This guide walks through deploying veilwarden to a Kubernetes cluster in under 5 minutes.

## Prerequisites Checklist

- [ ] Kubernetes 1.25+ cluster (kind, minikube, GKE, EKS, AKS)
- [ ] kubectl installed and configured
- [ ] Doppler token (or secret backend credentials)
- [ ] OPA policies ready (optional, can add later)

## Step-by-Step Deployment

### Step 1: Verify Manifests

```bash
# Verify all manifests are valid
./deploy/kubernetes/verify.sh
```

### Step 2: Create Required Secrets

```bash
# Create the veilwarden-secrets Secret
kubectl create secret generic veilwarden-secrets \
  -n veilwarden \
  --from-literal=session-secret=$(openssl rand -hex 32) \
  --from-literal=doppler-token=$DOPPLER_TOKEN \
  --dry-run=client -o yaml | kubectl apply -f -

# If using a different namespace, update accordingly
```

### Step 3: Create Policy ConfigMap (Optional)

If you have OPA policies ready:

```bash
# Example: Create from a policies directory
kubectl create configmap veilwarden-policies \
  -n veilwarden \
  --from-file=policies/ \
  --dry-run=client -o yaml | kubectl apply -f -
```

Or create an empty ConfigMap for now:

```bash
kubectl create configmap veilwarden-policies \
  -n veilwarden \
  --dry-run=client -o yaml | kubectl apply -f -
```

### Step 4: Deploy Veilwarden

```bash
# Deploy using kustomize
kubectl apply -k deploy/kubernetes/

# Expected output:
# namespace/veilwarden created
# serviceaccount/veilwarden created
# clusterrole.rbac.authorization.k8s.io/veilwarden-tokenreview created
# clusterrolebinding.rbac.authorization.k8s.io/veilwarden-tokenreview created
# configmap/veilwarden-config created
# daemonset.apps/veilwarden created
```

### Step 5: Verify Deployment

```bash
# Check DaemonSet status
kubectl get daemonset -n veilwarden

# Should show:
# NAME         DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE
# veilwarden   3         3         3       3            3

# Check pods
kubectl get pods -n veilwarden

# Check logs
kubectl logs -n veilwarden -l app=veilwarden --tail=50
```

### Step 6: Test from a Pod

```bash
# Create a test pod
kubectl run test-pod --rm -it --image=curlimages/curl -- sh

# Inside the pod, test authentication:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -v \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Upstream-Host: httpbin.org" \
  http://localhost:8088/headers

# You should see the request proxied through veilwarden
```

## Customization

### Change Image Tag

Edit `deploy/kubernetes/kustomization.yaml`:

```yaml
images:
- name: veilwarden
  newTag: v0.3.0  # Your version
```

Then redeploy:

```bash
kubectl apply -k deploy/kubernetes/
```

### Update Configuration

Edit `deploy/kubernetes/configmap.yaml` to add routes:

```yaml
data:
  config.yaml: |
    routes:
      - upstream_host: api.stripe.com
        upstream_scheme: https
        secret_id: STRIPE_SECRET_KEY
        inject_header: Authorization
        header_value_template: "Bearer {{secret}}"
```

Apply changes:

```bash
kubectl apply -f deploy/kubernetes/configmap.yaml

# Restart DaemonSet to pick up new config
kubectl rollout restart daemonset/veilwarden -n veilwarden
```

### Add OPA Policies

Create a Rego policy file:

```rego
# allow-production.rego
package veilwarden.authz

# Only production namespace can access Stripe
allow if {
    input.namespace == "production"
    input.upstream_host == "api.stripe.com"
}
```

Update the ConfigMap:

```bash
kubectl create configmap veilwarden-policies \
  -n veilwarden \
  --from-file=allow-production.rego \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart to load new policies
kubectl rollout restart daemonset/veilwarden -n veilwarden
```

## Troubleshooting

### Pods Won't Start

```bash
# Check events
kubectl get events -n veilwarden --sort-by='.lastTimestamp'

# Check pod status
kubectl describe pod -n veilwarden -l app=veilwarden

# Common issues:
# 1. Missing veilwarden-secrets Secret
# 2. Missing veilwarden-policies ConfigMap
# 3. Image pull errors
```

### Authentication Failures

```bash
# Verify RBAC permissions
kubectl auth can-i create tokenreviews.authentication.k8s.io \
  --as=system:serviceaccount:veilwarden:veilwarden

# Should output: yes

# Check logs for auth errors
kubectl logs -n veilwarden -l app=veilwarden | grep -i "auth"
```

### Policy Denials

```bash
# Check policy evaluation logs
kubectl logs -n veilwarden -l app=veilwarden | grep -i "policy"

# Verify policy ConfigMap exists
kubectl get configmap veilwarden-policies -n veilwarden

# View policy content
kubectl get configmap veilwarden-policies -n veilwarden -o yaml
```

## Deployment Patterns

### Local Development (kind)

```bash
# Create kind cluster
kind create cluster --name veilwarden-test

# Build and load image
docker build -t veilwarden:dev .
kind load docker-image veilwarden:dev --name veilwarden-test

# Update kustomization.yaml to use dev tag
# Then deploy
kubectl apply -k deploy/kubernetes/
```

### Production (GKE/EKS/AKS)

1. Build and push image to your registry:
   ```bash
   docker build -t your-registry/veilwarden:v0.2.0 .
   docker push your-registry/veilwarden:v0.2.0
   ```

2. Update `kustomization.yaml`:
   ```yaml
   images:
   - name: veilwarden
     newName: your-registry/veilwarden
     newTag: v0.2.0
   ```

3. Deploy:
   ```bash
   kubectl apply -k deploy/kubernetes/
   ```

### Multi-Environment (Staging, Production)

Create overlays:

```bash
deploy/kubernetes/
├── base/
│   ├── namespace.yaml
│   ├── ...
│   └── kustomization.yaml
└── overlays/
    ├── staging/
    │   ├── kustomization.yaml
    │   └── configmap-patch.yaml
    └── production/
        ├── kustomization.yaml
        └── configmap-patch.yaml
```

Deploy to staging:
```bash
kubectl apply -k deploy/kubernetes/overlays/staging/
```

## Monitoring

### View Logs

```bash
# Real-time logs from all pods
kubectl logs -f -n veilwarden -l app=veilwarden

# Logs from specific pod
kubectl logs -n veilwarden veilwarden-xxxxx

# Last 100 lines
kubectl logs -n veilwarden -l app=veilwarden --tail=100
```

### Health Checks

```bash
# Check liveness
kubectl exec -n veilwarden -it <pod-name> -- \
  wget -qO- http://localhost:8088/healthz

# Check readiness
kubectl describe pod -n veilwarden <pod-name> | grep -A5 "Readiness"
```

### Metrics (if Prometheus is enabled)

```bash
# Port-forward to access metrics
kubectl port-forward -n veilwarden <pod-name> 8088:8088

# Access metrics endpoint
curl http://localhost:8088/metrics
```

## Cleanup

### Remove Deployment

```bash
# Delete all resources
kubectl delete -k deploy/kubernetes/

# Or delete namespace (removes everything)
kubectl delete namespace veilwarden
```

### Clean up Cluster (kind)

```bash
kind delete cluster --name veilwarden-test
```

## Next Steps

- [ ] Review the full documentation: `deploy/kubernetes/README.md`
- [ ] Add custom routes to `configmap.yaml`
- [ ] Create OPA policies for access control
- [ ] Set up monitoring and alerting
- [ ] Configure NetworkPolicies for security
- [ ] Test failover and high availability

## Support

- Full README: `deploy/kubernetes/README.md`
- Design doc: `docs/kubernetes-workload-identity.md`
- Implementation plan: `docs/kubernetes-implementation-plan.md`
- GitHub Issues: https://github.com/yourusername/veilwarden/issues
