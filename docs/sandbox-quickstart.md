# Sandbox Quickstart Guide

Run AI agents in isolated sandboxes with VeilWarden.

## Prerequisites

1. **Install veil CLI**:
   ```bash
   go build -o veil ./cmd/veil
   # or
   go install github.com/yourusername/veilwarden/cmd/veil@latest
   ```

2. **Sandbox backend** (one of):
   - **macOS**: Built-in `sandbox-exec` (no installation needed)
   - **srt**: [Anthropic sandbox-runtime](https://www.npmjs.com/package/@anthropic-ai/sandbox-runtime) (`npm install -g @anthropic-ai/sandbox-runtime`)

## Quick Start

### 1. Create Configuration

Create `~/.veilwarden/config.yaml`:

```yaml
routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

sandbox:
  enabled: true
  backend: auto                    # auto, seatbelt, or srt
  working_dir: ~/my-project
  allowed_write_paths:
    - ~/my-project
    - /tmp
  denied_read_paths:
    - ~/.ssh
    - ~/.aws
    - ~/.gnupg
    - ~/.doppler
```

### 2. Set API Keys

```bash
# Option 1: Environment variables
export OPENAI_API_KEY=sk-...

# Option 2: Doppler (recommended - agent never sees keys)
export DOPPLER_TOKEN=dp.st.dev.xxxxx
```

### 3. Run Your Agent

```bash
veil exec -- python agent.py
```

The agent runs inside a sandbox with:
- Write access only to `allowed_write_paths`
- No read access to `denied_read_paths` (~/.ssh, ~/.aws, etc.)
- Network access only through the veil proxy
- Secrets injected transparently (agent never sees raw keys)

## Sandbox Backends

| Backend | OS | Description |
|---------|-----|-------------|
| `auto` | macOS/Linux | Best available (seatbelt on macOS) |
| `seatbelt` | macOS only | Uses `sandbox-exec` |
| `srt` | macOS | Anthropic sandbox-runtime |
| `bubblewrap` | Linux | Uses `bwrap` (coming soon) |

## Configuration Options

```yaml
sandbox:
  # Enable/disable sandbox
  enabled: true

  # Backend selection
  backend: auto  # auto | seatbelt | srt

  # Working directory for the agent
  working_dir: ~/my-project

  # Directories the agent can write to
  allowed_write_paths:
    - ~/my-project
    - /tmp

  # Directories the agent cannot read (blocked)
  denied_read_paths:
    - ~/.ssh
    - ~/.aws
    - ~/.gnupg
    - ~/.doppler
    - ~/.config/gcloud

  # Additional directories the agent can read (optional)
  allowed_read_paths:
    - /usr/local/lib/python3
```

## CLI Flags

```bash
# Force enable sandbox (override config)
veil exec --sandbox -- python agent.py

# Force disable sandbox (override config)
veil exec --no-sandbox -- python agent.py

# Verbose output (shows sandbox status)
veil exec --verbose -- python agent.py
```

## Security Model

**What the sandbox protects:**
- Prevents reading `~/.ssh/`, `~/.aws/`, `~/.gnupg/` etc.
- Prevents writing outside allowed directories
- Strips `DOPPLER_TOKEN` from environment
- Forces all network through the proxy

**What the sandbox does NOT protect:**
- Other environment variables (use Doppler to avoid exposing secrets)
- Resource exhaustion (CPU, memory, disk)
- Kernel exploits

**Defense in depth:**
1. **Sandbox** isolates filesystem
2. **Proxy** controls and logs network access
3. **OPA policies** enforce API restrictions
4. **Secret injection** prevents credential exposure

## Troubleshooting

### "sandbox-exec not found" (macOS)
This is built into macOS. If missing, your PATH may be misconfigured.

### "srt not found"
```bash
npm install -g @anthropic-ai/sandbox-runtime
which srt
```

### "permission denied" on working directory
Ensure the directory exists and is writable:
```bash
mkdir -p ~/my-project
chmod 755 ~/my-project
```

### Agent can't access files
Check that the file's directory is in `allowed_write_paths` or not in `denied_read_paths`.

### Network requests fail
Ensure the proxy is running (use `--verbose` to debug):
```bash
veil exec --verbose -- curl https://api.openai.com/v1/models
```

## Examples

### Minimal sandbox (AI agent workspace)
```yaml
sandbox:
  enabled: true
  backend: auto
  working_dir: ~/agent-workspace
  allowed_write_paths: [~/agent-workspace]
  denied_read_paths: [~/.ssh, ~/.aws]
```

### With Doppler and OPA policies
```yaml
routes:
  - host: api.github.com
    secret_id: GITHUB_TOKEN
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

doppler:
  project: my-project
  config: dev

policy:
  enabled: true
  engine: opa
  policy_path: ~/.veilwarden/policies
  decision_path: veilwarden/authz/allow

sandbox:
  enabled: true
  backend: auto
  working_dir: ~/code
  allowed_write_paths: [~/code, /tmp]
  denied_read_paths: [~/.ssh, ~/.aws, ~/.gnupg]
```

## Further Reading

- [Getting Started](getting-started.md) - Full walkthrough with GitHub example
- [Security Documentation](SECURITY.md) - Threat model and limitations
