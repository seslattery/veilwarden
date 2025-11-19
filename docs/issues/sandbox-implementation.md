# Implement Sandbox Mode for Veil CLI

## Background

The `--sandbox` flag is declared in `veil exec` but currently returns an error stating it's not implemented. This issue tracks the work to actually implement filesystem isolation for untrusted agents.

## Goal

Enable `veil exec --sandbox -- <command>` to run the command in a sandboxed environment with restricted filesystem access.

## Potential Approaches

1. **anthropic/sandbox-runtime**: Official Anthropic sandbox with Docker backend
2. **gVisor**: Lightweight application kernel for container isolation
3. **Bubblewrap**: Unprivileged sandboxing tool for Linux
4. **Custom seccomp/AppArmor**: Kernel-level syscall filtering

## Requirements

- Filesystem isolation (read-only mounts, restricted paths)
- Network access (needs to connect to proxy on localhost)
- Process isolation
- Works on Linux and macOS
- Minimal performance overhead

## Implementation Plan

TBD - requires research and design phase

## Related

- Security fixes design: docs/plans/2025-11-19-security-fixes-design.md
- Original MITM design: docs/plans/2025-11-18-laptop-mitm-proxy-design.md
