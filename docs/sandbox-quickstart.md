# Sandbox Quickstart Guide

Run AI agents in isolated sandboxes with VeilWarden.

## Prerequisites

1. **Install veil CLI**:
   ```bash
   go install github.com/yourusername/veilwarden/cmd/veil@latest
   ```

2. **Install Anthropic sandbox**:
   ```bash
   # Visit: https://github.com/anthropics/sandbox
   # Follow installation instructions
   anthropic-sandbox --version
   ```

## Quick Start

### 1. Initialize Configuration

```bash
veil init
```

This creates `~/.veilwarden/config.yaml`.

### 2. Enable Sandbox

Edit `~/.veilwarden/config.yaml`:

```yaml
routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

sandbox:
  enabled: true
  backend: anthropic
  working_dir: /workspace
  mounts:
    - host: ./project
      container: /workspace
      readonly: false
```

### 3. Set API Keys

```bash
# Option 1: Environment variables
export OPENAI_API_KEY=sk-...

# Option 2: Doppler (recommended)
export DOPPLER_TOKEN=dp.st.dev.xxxxx
```

### 4. Run Your Agent

```bash
veil exec -- python agent.py
```

The agent runs inside a sandbox with:
- Access to mounted directories (`./project` -> `/workspace`)
- Network access through veil proxy (with secret injection)
- No access to `~/.ssh/`, `~/.aws/`, or other sensitive files
- No access to system directories

## Mount Configuration

### Read-Write Mount (Agent Data)

```yaml
mounts:
  - host: ./project
    container: /workspace
    readonly: false
```

Agent can read and write files. Data persists between runs.

### Read-Only Mount (System Libraries)

```yaml
mounts:
  - host: /usr/local/lib/python3.11
    container: /usr/local/lib/python3.11
    readonly: true
```

Agent can read but not modify.

### Persistent Cache

```yaml
mounts:
  - host: ~/.cache/agent-data
    container: /data
    readonly: false
```

Agent state persists across runs in isolated directory.

## CLI Flags

```bash
# Force enable sandbox
veil exec --sandbox -- python agent.py

# Force disable sandbox
veil exec --no-sandbox -- python agent.py

# Verbose output
veil exec --verbose -- python agent.py
```

## Security Model

**Filesystem Isolation:**
- Agent sees ONLY mounted directories
- Cannot read `~/.ssh/`, `~/.aws/`, `/etc/passwd`, etc.
- Cannot write to system directories

**Network Control:**
- All traffic goes through veil MITM proxy
- OPA policies enforce allowed APIs/paths
- Secrets injected by veil (agent never sees raw keys)

**Defense in Depth:**
1. Sandbox isolates filesystem
2. veil proxy controls network
3. OPA policies enforce business logic
4. Secret injection prevents credential exposure

## Troubleshooting

### "anthropic-sandbox CLI not found"

```bash
# Install from GitHub
# Visit: https://github.com/anthropics/sandbox

# Verify installation
anthropic-sandbox --version

# Or disable sandbox
veil exec --no-sandbox -- python agent.py
```

### "host path does not exist: /some/path"

Check that mount paths exist:

```bash
# Create directory if needed
mkdir -p ./project

# Or use absolute path
ls -la ~/.cache/agent-data
```

### "container path must be absolute"

Container paths must start with `/`:

```yaml
# Correct
container: /workspace

# Wrong
container: workspace
```

### Sensitive Path Warning

```
WARNING: Mounting sensitive directory: /home/user/.ssh
```

This warns that you're giving the agent access to sensitive files. Only proceed if you trust the agent completely.

## Examples

See `examples/veil-sandbox-config.yaml` for complete configuration.

## Further Reading

- [Sandbox Design](plans/2025-11-21-sandbox-integration-design.md)
- [Security Documentation](SECURITY.md)
- [OPA Integration](opa-integration.md)
