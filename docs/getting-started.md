# Getting Started with VeilWarden

VeilWarden is a security proxy that lets you safely give AI agents access to APIs without exposing your credentials. It works by intercepting HTTP requests and injecting secrets transparently, while running agents in a sandbox that prevents credential theft.

## The Problem

You want an AI agent to interact with GitHub on your behalf, but:
- You don't want to give it your GitHub token directly (it could exfiltrate it)
- You want to limit what API endpoints it can access
- You want to prevent it from accessing sensitive files on your system

## The Solution

VeilWarden acts as a transparent proxy that:
1. **Injects credentials** into HTTP requests automatically
2. **Enforces policies** on what APIs the agent can call
3. **Sandboxes the agent** to prevent credential theft and file access

## Quick Start

### 1. Install VeilWarden

```bash
go install github.com/yourusername/veilwarden/cmd/veil@latest
```

Or build from source:
```bash
git clone https://github.com/yourusername/veilwarden
cd veilwarden
go build -o veil ./cmd/veil
```

### 2. Store Your Secrets in Doppler

VeilWarden uses [Doppler](https://doppler.com) to manage secrets securely.

```bash
# Install Doppler CLI
brew install dopplerhq/cli/doppler

# Login and setup
doppler login
doppler setup

# Add your GitHub token
doppler secrets set GITHUB_TOKEN
```

### 3. Create a Configuration File

Create `~/.veilwarden/config.yaml`:

```yaml
# Route configuration - which secrets to inject for which hosts
routes:
  - host: "api.github.com"
    secret_id: "GITHUB_TOKEN"
    header_name: "Authorization"
    header_value_template: "Bearer {{secret}}"

# Doppler configuration
doppler:
  project: "my-project"
  config: "dev"

# Policy enforcement (optional but recommended)
policy:
  enabled: true
  engine: opa
  policy_path: ~/.veilwarden/policies
  decision_path: veilwarden/authz/allow

# Sandbox configuration
sandbox:
  enabled: true
  backend: auto  # Uses seatbelt on macOS, bubblewrap on Linux
  working_dir: ~/agent-workspace
  allowed_write_paths:
    - ~/agent-workspace
  denied_read_paths:
    - ~/.ssh
    - ~/.aws
    - ~/.gnupg
    - ~/.doppler
```

### 4. Create an OPA Policy (Optional)

Create `~/.veilwarden/policies/github.rego`:

```rego
package veilwarden.authz

import rego.v1

default allow := false

# Allow HTTPS proxy connections
allow if {
    input.method == "CONNECT"
}

# Allow read-only GitHub API operations
allow if {
    input.host == "api.github.com"
    input.method == "GET"
}

# Allow creating issues
allow if {
    input.host == "api.github.com"
    input.method == "POST"
    startswith(input.path, "/repos/")
    endswith(input.path, "/issues")
}

# Allow creating pull request comments
allow if {
    input.host == "api.github.com"
    input.method == "POST"
    contains(input.path, "/pulls/")
    endswith(input.path, "/comments")
}

# Deny dangerous operations
deny if {
    input.host == "api.github.com"
    input.method == "DELETE"
}

deny if {
    input.host == "api.github.com"
    input.path == "/user/repos"
    input.method == "POST"  # Don't let agent create repos
}
```

### 5. Run Your Agent Through VeilWarden

```bash
# Set your Doppler token (or use doppler run)
export DOPPLER_TOKEN=$(doppler configure get token --plain)

# Run any command through VeilWarden
veil exec -- python my_agent.py

# Or run a simple test with curl
veil exec -- curl https://api.github.com/user
```

## What Happens Under the Hood

When you run `veil exec -- python my_agent.py`:

1. **Proxy starts**: VeilWarden starts a local MITM proxy with an ephemeral CA certificate
2. **Secrets fetched**: Credentials are fetched from Doppler (cached for performance)
3. **Sandbox created**: Your agent runs in an isolated environment where:
   - `DOPPLER_TOKEN` is stripped from the environment
   - Network access is restricted to only the proxy
   - Filesystem access is controlled
4. **Requests intercepted**: When the agent makes an HTTP request to `api.github.com`:
   - The proxy checks the OPA policy
   - If allowed, it injects the `Authorization: Bearer <token>` header
   - The request is forwarded to GitHub
5. **Agent never sees the token**: The credential injection happens in the proxy, not in the agent's environment

## Example: AI Agent with GitHub Access

Here's a simple Python agent that can interact with GitHub safely:

```python
#!/usr/bin/env python3
"""Example agent that interacts with GitHub through VeilWarden."""

import os
import json
import urllib.request
import ssl

def github_api(path, method="GET", data=None):
    """Make a GitHub API request (credentials injected by VeilWarden)."""
    url = f"https://api.github.com{path}"

    # Create SSL context with VeilWarden's CA cert
    ctx = ssl.create_default_context()
    ca_cert = os.environ.get('SSL_CERT_FILE')
    if ca_cert:
        ctx.load_verify_locations(ca_cert)

    req = urllib.request.Request(url, method=method)
    req.add_header('Accept', 'application/vnd.github.v3+json')
    req.add_header('User-Agent', 'VeilWarden-Agent')

    if data:
        req.data = json.dumps(data).encode('utf-8')
        req.add_header('Content-Type', 'application/json')

    # Note: We don't set Authorization header - VeilWarden injects it!
    with urllib.request.urlopen(req, context=ctx) as resp:
        return json.loads(resp.read().decode('utf-8'))

def main():
    # Get authenticated user (proves credentials work)
    user = github_api("/user")
    print(f"Authenticated as: {user['login']}")

    # List repositories
    repos = github_api("/user/repos?per_page=5")
    print(f"\nYour repositories:")
    for repo in repos:
        print(f"  - {repo['full_name']}")

    # The agent CANNOT access the actual token
    print(f"\nDOPPLER_TOKEN in env: {'DOPPLER_TOKEN' in os.environ}")  # False!

    # The agent CANNOT make unauthorized requests
    # This would be blocked by the OPA policy:
    # github_api("/user/repos", method="POST", data={"name": "hacked-repo"})

if __name__ == "__main__":
    main()
```

Run it:

```bash
veil exec -- python github_agent.py
```

Output:
```
Authenticated as: your-username

Your repositories:
  - your-username/project1
  - your-username/project2
  - your-username/project3

DOPPLER_TOKEN in env: False
```

## Security Features

### Credential Isolation
- The agent never sees `DOPPLER_TOKEN` or the actual API tokens
- Credentials are injected at the proxy level, not passed to the agent
- Even if the agent is compromised, it cannot exfiltrate credentials

### Network Isolation
- The sandbox only allows connections to the VeilWarden proxy
- Direct network access is blocked (prevents credential exfiltration)
- DNS lookups to external servers are blocked

### Filesystem Isolation
- Sensitive directories (`~/.ssh`, `~/.aws`, etc.) are blocked
- Write access is limited to specified directories
- The agent cannot read your private keys or cloud credentials

### Policy Enforcement
- OPA policies control which API endpoints the agent can access
- You can allow read-only access while blocking writes
- Policies are evaluated before credentials are injected

## Next Steps

- [Sandbox Configuration](./sandbox-quickstart.md) - Deep dive into sandbox options
- [OPA Policy Examples](./policies/) - More policy examples
- [Security Model](./SECURITY.md) - Understanding the threat model

## Troubleshooting

### Agent can't connect
```bash
# Run with verbose logging
veil exec --verbose -- curl https://api.github.com/user
```

### Policy denying requests
Check the decision path matches your policy:
```bash
# Test your policy
opa eval -d ~/.veilwarden/policies -i input.json "data.veilwarden.authz.allow"
```

### Sandbox issues
```bash
# Try without sandbox first
veil exec --no-sandbox -- curl https://api.github.com/user

# Check which backends are available
which srt        # Anthropic sandbox-runtime
which sandbox-exec  # macOS seatbelt
```
