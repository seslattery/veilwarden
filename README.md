````md
![veilwarden](https://github.com/user-attachments/assets/a943fe76-1e34-48b7-80f1-89b48cedd593)

# Veilwarden

> **Run powerful AI agents without ever handing them your secrets.**
> Credential injection at the network layer + locked-down sandbox isolation.

Veilwarden is a sidecar proxy + sandbox that lets you give AI agents real API access **without** giving them:

- **Your API keys** – secrets are injected at the network layer, never into code or env
- **Your dotfiles & creds** – sandbox blocks `~/.ssh`, `~/.aws`, `~/.config`, etc.
- **A way around the proxy** – network isolation forces all traffic through Veilwarden
- **Unlimited reach** – OPA policies control *which* APIs and endpoints they can call

```text
┌─────────────────────────────────────────────────────────────────┐
│                             SANDBOX                            │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐     │
│  │  AI Agent   │ ──── │  Veilwarden │ ──── │   APIs      │     │
│  │  (no keys)  │      │ (injects    │      │ (OpenAI,    │     │
│  │             │      │   secrets)  │      │  etc.)      │     │
│  └─────────────┘      └─────────────┘      └─────────────┘     │
│        │                                                        │
│        ├── ✗ Can't read ~/.ssh, ~/.aws, ~/.config              │
│        ├── ✗ Can't bypass proxy (network isolated)             │
│        └── ✗ Can't see DOPPLER_TOKEN or raw credentials        │
└─────────────────────────────────────────────────────────────────┘
````

> **Status:** Experimental – APIs may change; security hardening is ongoing.

---

## Why Veilwarden?

Modern AI agents are **powerful** and **unpredictable**. They browse the web, call tools, and hit APIs—often with full access to your environment.

Veilwarden gives you:

* 🧱 **Zero-trust agents**
  Agents never see raw secrets. Keys are added to requests *after* they leave the process.

* 🛡️ **Defense in depth**
  Even if the agent is prompt-injected, jailbroken, or outright malicious, it can’t:

  * Read SSH keys, cloud creds, or Doppler tokens
  * Reach the network without going through the proxy
  * Call APIs you haven’t explicitly allowed

* 🎛 **Centralized control**
  Manage routes, secrets, and OPA policies in one place instead of sprinkling config across scripts and tools.

* 🧩 **Drop-in integration**
  No SDKs, no code changes. Works with any HTTP client that honors proxy env vars (`HTTP_PROXY`, `HTTPS_PROXY`).

---

## Quick Start

```bash
# Install
go install github.com/yourusername/veilwarden/cmd/veil@latest

# Initialize config
veil init

# Set your API keys (env or Doppler)
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...

# Run any command through the proxy
veil exec -- python my_agent.py
veil exec -- curl https://api.openai.com/v1/models

# Run with sandbox enabled (recommended for untrusted agents)
veil exec --sandbox -- python untrusted_agent.py
```

Your agent keeps making normal HTTP requests. Veilwarden:

1. Intercepts the outbound request
2. Looks up the route for the target host
3. Injects the appropriate `Authorization` or custom header
4. Applies policy (OPA) and network / filesystem sandboxing if enabled

With `--sandbox`, the agent runs in an isolated environment that:

* Blocks access to sensitive files
* Forces all network traffic through Veilwarden
* Prevents direct TCP / DNS exfiltration

---

## Configuration

Config lives at `~/.veilwarden/config.yaml`.

```bash
veil init   # Creates the initial config file
```

### Routes (Required)

Map destination hosts to secrets and headers:

```yaml
routes:
  - host: api.openai.com
    secret_id: OPENAI_API_KEY
    header_name: Authorization
    header_value_template: "Bearer {{secret}}"

  - host: api.anthropic.com
    secret_id: ANTHROPIC_API_KEY
    header_name: x-api-key
    header_value_template: "{{secret}}"
```

When a request goes to `api.openai.com`, Veilwarden:

* Resolves `secret_id` → actual secret (env or Doppler)
* Renders `header_value_template`
* Injects the header on the wire

### Secrets

#### Option A: Environment variables (default)

Secrets are read from env vars matching `secret_id`:

```bash
export OPENAI_API_KEY=sk-...
veil exec -- python agent.py
```

#### Option B: Doppler (recommended for teams)

Use Doppler as a centralized secret store:

```yaml
doppler:
  project: my-project
  config: dev
```

```bash
export DOPPLER_TOKEN=dp.st.xxx
veil exec -- python agent.py
```

If Doppler is configured but `DOPPLER_TOKEN` is missing, Veilwarden falls back to environment variables.

---

### Policy (Optional, but powerful)

Use [OPA](https://www.openpolicyagent.org/) to enforce *which* requests are allowed:

```yaml
policy:
  engine: opa
  policy_path: ~/.veilwarden/policies
  decision_path: veilwarden/authz/allow
```

| Field | Purpose |
|-------|---------|
| `policy_path` | Filesystem directory containing `.rego` files |
| `decision_path` | OPA query path (`<package>/<rule>`) to evaluate for allow/deny |

All `.rego` files in `policy_path` are loaded, but only `decision_path` is queried per request. This lets you split policies across multiple files while having a single entrypoint.

Example decisions you can encode:

* “Only allow `POST /v1/chat/completions` to `api.openai.com`.”
* “Block requests with bodies larger than N KB.”
* “Deny outbound calls to unknown hosts.”

See `policies/example.rego` for examples.

---

## Sandbox Isolation

The sandbox is the second half of Veilwarden’s security story: it keeps agents from rummaging through your machine or sneaking traffic around the proxy.

When enabled, agents run with:

### Network Isolation

* ✅ All traffic forced through Veilwarden’s proxy
* ✅ Direct TCP connections blocked (no bypassing the proxy)
* ✅ DNS resolution controlled (reduces data-exfil via DNS tricks)
* ✅ Raw socket creation blocked

### Filesystem Isolation

The sandbox uses an **asymmetric security model**:

| Operation | Default | Config |
|-----------|---------|--------|
| **Writes** | ❌ Denied everywhere | `allowed_write_paths` to permit |
| **Reads** | ✅ Allowed everywhere | `denied_read_paths` to block |

This design lets programs read system files they need (`/usr/lib`, `/etc/hosts`, etc.) while preventing writes outside your project. Sensitive paths must be explicitly blocked.

**Protections:**
* ✅ Writes denied by default—only `allowed_write_paths` are writable
* ✅ Sensitive directories blocked via `denied_read_paths`
* ✅ Symlink / hardlink tricks mitigated
* ✅ Path traversal (`../../..`) blocked

**Recommended `denied_read_paths`** (see `examples/claude-code/config.yaml`):
```
~/.ssh, ~/.aws, ~/.config/gcloud, ~/.kube, ~/.docker,
~/.doppler, ~/.gnupg, ~/.vault-token, ~/.anthropic,
~/.netrc, ~/.git-credentials, ~/.npmrc, ~/.pypirc,
~/.bash_history, ~/.zsh_history
```

Example config:

```yaml
sandbox:
  enabled: true
  backend: auto                    # auto | seatbelt | srt
  working_dir: ./my-project
  allowed_write_paths:
    - ./my-project                 # Agent can write here
    - /tmp/agent-workspace
  denied_read_paths:
    - ~/.ssh
    - ~/.aws
    - ~/.config/gcloud
    - ~/secrets                    # Add your own sensitive paths
```

### Backends

| Backend    | Platform    | Implementation                                                                                  |
| ---------- | ----------- | ----------------------------------------------------------------------------------------------- |
| `auto`     | macOS/Linux | Uses the native sandbox backend (recommended)                                                   |
| `seatbelt` | macOS       | Uses `sandbox-exec` / seatbelt profiles                                                         |
| `srt`      | Any         | Uses Anthropic's [sandbox-runtime](https://www.npmjs.com/package/@anthropic-ai/sandbox-runtime) |

### Environment Variable Stripping

Veilwarden automatically strips environment variables that look like secrets:

* **Pattern-based:** `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_CREDENTIAL`, `*_AUTH`, `*_PRIVATE`
* **Known sensitive:** `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `KUBECONFIG`, `GOOGLE_APPLICATION_CREDENTIALS`, etc.

Non-secret vars (`PATH`, `HOME`, `EDITOR`, `NODE_ENV`, etc.) pass through normally.

**Need to pass a specific secret-like var?** Use `env_passthrough`:

```yaml
sandbox:
  enabled: true
  backend: auto
  env_passthrough:
    - MY_CUSTOM_TOKEN      # Explicitly allow this through
    - LEGACY_API_KEY       # And this one
```

See [Sandbox Quickstart](docs/sandbox-quickstart.md) for detailed setup and limitations.

---

## CLI Reference

```bash
veil init                         # Create default config
veil exec -- <command>            # Run command through proxy
veil exec --sandbox -- <cmd>      # Force sandbox on
veil exec --no-sandbox -- <cmd>   # Force sandbox off
veil exec --verbose -- <cmd>      # Log proxy activity
```

Common patterns:

```bash
# Run a local dev server with protected API access
veil exec --sandbox -- npm run dev

# Test a one-off curl without exposing keys to shell history
veil exec -- curl https://api.openai.com/v1/models
```

---

## Security Model

Veilwarden aims for **defense in depth** rather than “magic bullet” security.

### Layers

| Layer                    | What it does                        | What it mitigates                       |
| ------------------------ | ----------------------------------- | --------------------------------------- |
| **Credential Injection** | Adds secrets only at network layer  | Agent code never sees API keys          |
| **Network Isolation**    | Forces traffic through proxy        | Proxy bypass & blind exfiltration       |
| **Filesystem Sandbox**   | Blocks sensitive paths              | Reading SSH keys, cloud creds, dotfiles |
| **OPA Policies**         | Enforces fine-grained request rules | Overbroad or unexpected API usage       |
| **Env Stripping**        | Removes secret-like env vars        | Agent can't see `*_KEY`, `*_TOKEN`, etc |

### In Practice

With Veilwarden in front of your agents:

* They *can* call OpenAI/Anthropic (or any HTTP API you route)
* They *cannot*:

  * Read `~/.ssh/id_ed25519`
  * Grab `~/.aws/credentials` or `~/.config/gcloud`
  * Reach random hosts without going through the proxy
  * See env vars like `OPENAI_API_KEY`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`
  * Hit disallowed endpoints if you enforce OPA policies

### Limitations

* Env stripping uses heuristics (`*_KEY`, `*_TOKEN`, `*_SECRET`, etc.). Secrets with
  unusual names may slip through—use `env_passthrough` to explicitly allow vars you need.
* Sandbox and backends are experimental; expect rough edges.
* OPA defaults to **allow all** if you don't provide policies (for compatibility).

For a full threat model and assumptions, see [SECURITY.md](docs/SECURITY.md).

---

## Development

```bash
# Setup
just setup

# Test
just test          # All tests
just test-veil     # CLI tests only
just test-e2e      # E2E tests (requires DOPPLER_TOKEN + srt)

# Build
just build         # Output: bin/veil
```

Prerequisites:

* Go 1.21+
* [`just`](https://github.com/casey/just) (optional but recommended)

```
```
