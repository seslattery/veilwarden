# Kubernetes Usage Guide

## Installation

### Prerequisites
- Kubernetes 1.25+
- Doppler account (or other secret backend)
- kubectl configured

### Deploy with kubectl

Deploy veilwarden to your cluster:

```bash
kubectl apply -k deploy/kubernetes/
```

This creates:
- Namespace: `veilwarden`
- ServiceAccount: `veilwarden` with TokenReview permissions
- DaemonSet: One proxy pod per node on `localhost:8088`

### Configure Secrets

Create secret with Doppler credentials:

```bash
kubectl create secret generic veilwarden-secrets \
  -n veilwarden \
  --from-literal=session-secret=$(openssl rand -hex 32) \
  --from-literal=doppler-token=$DOPPLER_TOKEN
```

## Using from Application Pods

### Method 1: Direct API calls

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

    req, _ := http.NewRequest("GET", "http://localhost:8088/v1/charges", nil)
    req.Header.Set("Authorization", "Bearer "+string(token))
    req.Header.Set("X-Upstream-Host", "api.stripe.com")

    resp, _ := http.DefaultClient.Do(req)
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
}
```

### Method 2: HTTP_PROXY environment variable

Configure your application to use veilwarden as HTTP proxy:

```yaml
env:
- name: HTTP_PROXY
  value: "http://localhost:8088"
- name: HTTPS_PROXY
  value: "http://localhost:8088"
```

## Policy Examples

See `policies/kubernetes-example.rego` for production policy patterns.

## Troubleshooting

### Pods can't authenticate

Check RBAC permissions:
```bash
kubectl auth can-i create tokenreviews.authentication.k8s.io \
  --as=system:serviceaccount:veilwarden:veilwarden
```

### Policy denials

Check veilwarden logs:
```bash
kubectl logs -n veilwarden -l app=veilwarden | grep policy
```
