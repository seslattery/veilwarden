# Warden: Native Sandbox Implementation

**Date:** 2025-12-03
**Status:** Design Complete

## Overview

Warden is a Go library (`pkg/warden`) that provides OS-level sandboxing for running untrusted commands with filesystem and network isolation. It replaces the external `srt` dependency with a native implementation.

**Goals:**
- Single `veil` binary with no npm/external dependencies
- Pluggable backends: native (seatbelt/bubblewrap) or external (srt)
- Feature parity with srt's isolation model
- Library-first design for reuse beyond veil

## Threat Model

**What we protect against:**
- Untrusted code with user-level privileges
- Exfiltration of host secrets (~/.ssh, ~/.aws, API keys)
- Unauthorized network access (bypassing the proxy)
- Filesystem tampering outside designated paths

**What we do NOT protect against:**
- Kernel exploits / privilege escalation via 0-days
- Resource exhaustion (no cgroup limits in v1)
- Physical host compromise
- Malicious actors with root access

> This is NOT a full container like Docker/gVisor/Firecracker. It's application-level sandboxing suitable for running untrusted AI agents, not for multi-tenant isolation.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    warden.Backend                        │
│                     (interface)                          │
└───────┬───────────────┬───────────────┬─────────────────┘
        │               │               │
┌───────▼───────┐ ┌─────▼─────┐ ┌───────▼───────┐
│SeatbeltBackend│ │BubblewrapB│ │  SrtBackend   │
│   (macOS)     │ │  (Linux)   │ │  (external)   │
└───────────────┘ └───────────┘ └───────────────┘
```

**Runtime behavior:**
- `backend: auto` → `runtime.GOOS` selects seatbelt (darwin) or bubblewrap (linux)
- `backend: seatbelt` on Linux → error: "seatbelt only available on macOS"
- `backend: bubblewrap` on macOS → error: "bubblewrap only available on Linux"
- `backend: srt` → uses external srt CLI (requires npm install)
- Unsupported OS (Windows, etc.) → error with clear message

**Package structure:**

```
pkg/warden/
├── backend.go           # Interface + NewBackend() factory
├── config.go            # Config, validation, defaults
├── seatbelt.go          # macOS implementation
├── seatbelt_profile.go  # SBPL generation
├── seatbelt.sbpl.tmpl   # Embedded template
├── bubblewrap.go        # Linux implementation
├── netns.go             # Linux netns helper (subcommand)
├── bridge.go            # Linux bridge helper
├── seccomp.go           # Linux seccomp filter
├── srt.go               # External srt wrapper
├── glob.go              # Safe glob-to-regex conversion
├── paths.go             # Path validation, sensitive path list

cmd/warden/              # Future: standalone CLI wrapper
├── main.go
```

### Core Types

```go
// Backend interface for pluggable sandbox implementations
type Backend interface {
    Start(ctx context.Context, cfg *Config) (*Process, error)
}

// Process represents a running sandboxed process
type Process struct {
    PID    int
    Stdin  io.WriteCloser
    Stdout io.ReadCloser
    Stderr io.ReadCloser
    Wait   func() error  // Blocks until process exits, handles cleanup
}

// TODO: Add Kill() method for explicit termination
// TODO: Add Cancel() support that respects ctx.Done() for graceful shutdown
// For now, callers should use context cancellation passed to Start()
```

## Configuration

```yaml
sandbox:
  enabled: true
  backend: auto           # auto | seatbelt | bubblewrap | srt
  allowed_write_paths:
    - ./project
    - /tmp/agent-*        # Globs: macOS only (see limitations)
  denied_read_paths:
    - ~/.ssh
    - ~/.aws
    - ~/.config/*/credentials  # Globs: macOS only
  allowed_unix_sockets:   # DANGEROUS - see warnings below
    - /var/run/docker.sock
  enable_pty: false       # For interactive shells
  debug: false            # Disable seccomp, verbose logging
```

### Default Denied Read Paths

If `denied_read_paths` is empty, these are denied by default:

```go
var DefaultDeniedReadPaths = []string{
    "~/.ssh",
    "~/.aws",
    "~/.config/gcloud",
    "~/.azure",
    "~/.doppler",
    "~/.gnupg",
    "~/.kube",
    "~/.docker",
    "/etc/shadow",
    "/etc/sudoers",
}
```

### Proxy Address Validation

`ProxyAddr` must be a loopback address. Non-loopback addresses are rejected unless `unsafe_allow_remote_proxy: true` is set:

```go
func validateProxyAddr(addr string) error {
    host, _, err := net.SplitHostPort(addr)
    if err != nil {
        return err
    }

    // Allow localhost explicitly
    if host == "localhost" {
        return nil
    }

    // Must be a loopback IP (127.0.0.1, ::1, etc.)
    ip := net.ParseIP(host)
    if ip == nil || !ip.IsLoopback() {
        return fmt.Errorf("proxy must be loopback address (localhost/127.0.0.1/::1), got: %s", addr)
    }

    return nil
}
```

### Debug Mode Safeguards

`debug: true` is dangerous (disables seccomp). Protected by:

```go
if cfg.Debug {
    if os.Getenv("WARDEN_ALLOW_DEBUG") != "1" {
        return fmt.Errorf("debug mode requires WARDEN_ALLOW_DEBUG=1 environment variable")
    }
    log.Println("WARNING: debug mode enabled - seccomp disabled, security reduced")
}
```

---

## Seatbelt Backend (macOS)

Uses `sandbox-exec` with dynamically generated SBPL profiles.

### Profile Generation

Template-based approach with embedded `.sbpl.tmpl` file:

```go
//go:embed seatbelt.sbpl.tmpl
var seatbeltTemplate string

type profileData struct {
    DeniedReadLiterals    []string
    DeniedReadPatterns    []string  // Regex
    AllowedWriteLiterals  []string
    AllowedWritePatterns  []string  // Regex
    AllowedUnixSockets    []string
    ProxyPort             int
    EnablePTY             bool
}

func GenerateProfile(cfg *Config) (string, error) {
    data := buildProfileData(cfg)
    tmpl := template.Must(template.New("seatbelt").Parse(seatbeltTemplate))
    var buf bytes.Buffer
    tmpl.Execute(&buf, data)
    return buf.String(), nil
}
```

### SBPL Template

```scheme
(version 1)
(deny default)

;; === Process ===
(allow process-exec)
(allow process-fork)
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))
;; NOTE: mach-priv-task-port omitted - add only if tests require it

;; === Filesystem ===

;; Base: allow reads, deny writes
(allow file-read*)
(deny file-write*)

;; Deny reads - literal paths
{{range .DeniedReadLiterals}}
(deny file-read* (subpath "{{.}}"))
{{end}}

;; Deny reads - glob patterns
{{range .DeniedReadPatterns}}
(deny file-read* (regex #"{{.}}"))
{{end}}

;; Allow writes - literal paths
{{range .AllowedWriteLiterals}}
(allow file-write* (subpath "{{.}}"))
(allow file-write-unlink (subpath "{{.}}"))
{{end}}

;; Allow writes - glob patterns
{{range .AllowedWritePatterns}}
(allow file-write* (regex #"{{.}}"))
(allow file-write-unlink (regex #"{{.}}"))
{{end}}

;; Essential device writes
(allow file-write* (literal "/dev/null"))
(allow file-write* (literal "/dev/zero"))
(allow file-write* (literal "/dev/tty"))
(allow file-ioctl (literal "/dev/null"))
(allow file-ioctl (literal "/dev/tty"))

;; === Network ===

(deny network*)
(allow network-bind (local ip "localhost:*"))
(allow network-outbound (remote tcp "localhost:{{.ProxyPort}}"))
(allow network-outbound (remote tcp "127.0.0.1:{{.ProxyPort}}"))
(allow network-inbound (local tcp "localhost:*"))
(allow network-inbound (local tcp "127.0.0.1:*"))

;; === Unix Sockets ===
;; WARNING: Unix sockets like /var/run/docker.sock grant significant host access.
;; Only enable if you understand the implications.
{{range .AllowedUnixSockets}}
(allow file-read* (literal "{{.}}"))
(allow file-write* (literal "{{.}}"))
(allow file-ioctl (literal "{{.}}"))
{{end}}

;; === System Compatibility ===

;; IPC (needed for Python multiprocessing, etc.)
(allow ipc-posix-shm)
(allow ipc-posix-sem)

;; NOTE: mach-lookup is intentionally restricted.
;; Wide-open mach-lookup allows XPC to arbitrary system daemons.
;; Add specific services here only if needed:
;; (allow mach-lookup (global-name "com.apple.specific.service"))

;; User preferences (some libs check locale, etc.)
(allow user-preference-read)

;; System info
(allow sysctl-read)
(allow iokit-get-properties)

;; Device access
(allow file-read* (literal "/dev/null"))
(allow file-read* (literal "/dev/zero"))
(allow file-read* (literal "/dev/random"))
(allow file-read* (literal "/dev/urandom"))
(allow file-read* (literal "/dev/tty"))

{{if .EnablePTY}}
;; PTY support (interactive shells)
(allow pseudo-tty)
(allow file-read* (literal "/dev/ptmx"))
(allow file-read* (regex #"^/dev/ttys[0-9]+$"))
(allow file-write* (literal "/dev/ptmx"))
(allow file-write* (regex #"^/dev/ttys[0-9]+$"))
(allow file-ioctl (literal "/dev/ptmx"))
(allow file-ioctl (regex #"^/dev/ttys[0-9]+$"))
{{end}}
```

### macOS-Specific Notes

**mach-lookup:** Intentionally removed. Wide-open `(allow mach-lookup)` permits XPC communication with arbitrary system daemons, which is a privilege escalation risk. If specific services are needed (discovered through testing), add them individually.

**Unix sockets:** Use `file-*` operations, not `network*`. Unix sockets are filesystem nodes on macOS.

### Execution

```go
func (s *SeatbeltBackend) Start(ctx context.Context, cfg *Config) (*Process, error) {
    profile, err := GenerateProfile(cfg)
    if err != nil {
        return nil, err
    }

    if cfg.Debug {
        log.Printf("Seatbelt profile:\n%s", profile)
    }

    // Execute command directly (no /bin/sh -c wrapper)
    // This matches Linux behavior and avoids shell quoting issues.
    // If caller wants shell semantics, they can pass ["bash", "-c", "..."]
    args := append([]string{"-p", profile}, cfg.Command...)
    cmd := exec.CommandContext(ctx, "sandbox-exec", args...)
    cmd.Env = cfg.Env
    cmd.Dir = cfg.WorkingDir

    // Setup pipes...
    stdin, _ := cmd.StdinPipe()
    stdout, _ := cmd.StdoutPipe()
    stderr, _ := cmd.StderrPipe()

    if err := cmd.Start(); err != nil {
        return nil, err
    }

    return &Process{
        PID:    cmd.Process.Pid,
        Stdin:  stdin,
        Stdout: stdout,
        Stderr: stderr,
        Wait:   cmd.Wait,
    }, nil
}
```

---

## Bubblewrap Backend (Linux)

Uses Linux namespaces with a Unix socket bridge for network isolation.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Host                                                        │
│                                                              │
│  ┌─────────┐     ┌──────────────────┐     ┌──────────────┐  │
│  │  Proxy  │◄────│ warden bridge    │◄────│ Unix Socket  │  │
│  │ :8080   │     │ (goroutine)      │     │ /tmp/w-xxxxx │  │
│  └─────────┘     └──────────────────┘     └──────┬───────┘  │
│                                                   │          │
└───────────────────────────────────────────────────│──────────┘
                                                    │
┌───────────────────────────────────────────────────│──────────┐
│  Sandbox (bwrap --unshare-net --unshare-pid)      │          │
│                                                   │          │
│  ┌──────────────────┐     ┌──────────────────┐    │          │
│  │  Agent process   │────►│ warden netns     │────┘          │
│  │  HTTP_PROXY=     │     │ (listens :3128,  │               │
│  │  localhost:3128  │     │  per-conn dial)  │               │
│  └──────────────────┘     └──────────────────┘               │
└──────────────────────────────────────────────────────────────┘
```

**Security model:**
- `--unshare-net` creates empty network namespace (only `lo` interface)
- No way to reach external network - only path out is Unix socket to bridge
- Bridge only forwards to proxy (where OPA policies enforce access control)
- Seccomp filter restricts syscalls after setup
- Only `/run/warden/` is mounted, limiting Unix socket attack surface

### Single Binary Subcommands

```bash
warden bridge --sock /tmp/warden-xxx.sock --proxy 127.0.0.1:8080
warden netns --sock /run/warden/proxy.sock --listen 127.0.0.1:3128 \
    --drop-to 1000:1000 --exec python -- agent.py
```

### Bridge (Host Side)

Accepts one Unix connection per proxied TCP connection:

```go
type Bridge struct {
    listener  net.Listener
    proxyAddr string
    done      chan struct{}
}

func startBridge(sockPath, proxyAddr string) (*Bridge, error) {
    listener, err := net.Listen("unix", sockPath)
    if err != nil {
        return nil, err
    }

    b := &Bridge{
        listener:  listener,
        proxyAddr: proxyAddr,
        done:      make(chan struct{}),
    }
    go b.serve()
    return b, nil
}

func (b *Bridge) serve() {
    for {
        conn, err := b.listener.Accept()
        if err != nil {
            select {
            case <-b.done:
                return
            default:
                continue
            }
        }
        go b.handleConn(conn)
    }
}

func (b *Bridge) handleConn(sandboxConn net.Conn) {
    defer sandboxConn.Close()

    proxyConn, err := net.Dial("tcp", b.proxyAddr)
    if err != nil {
        return
    }
    defer proxyConn.Close()

    // Bidirectional copy
    done := make(chan struct{})
    go func() {
        io.Copy(proxyConn, sandboxConn)
        done <- struct{}{}
    }()
    io.Copy(sandboxConn, proxyConn)
    <-done
}

func (b *Bridge) Close() error {
    close(b.done)
    return b.listener.Close()
}
```

### Netns Helper (Sandbox Side)

Per-connection model: each accepted TCP connection dials a new Unix socket connection.

**Critical:** We must run the agent as a child process, NOT via `syscall.Exec`. `Exec` replaces the process image and kills the Go runtime, including the forwarding goroutine. The helper must stay alive to forward traffic.

```go
func netnsMain(sockPath, listenAddr string, dropUID, dropGID int, enablePTY bool, execCmd []string) error {
    // 1. Bring up loopback
    if err := exec.Command("ip", "link", "set", "lo", "up").Run(); err != nil {
        return fmt.Errorf("failed to bring up loopback: %w", err)
    }

    // 2. Start TCP listener
    listener, err := net.Listen("tcp", listenAddr)
    if err != nil {
        return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
    }

    // 3. Start forwarding goroutine (dials Unix socket per connection)
    go forwardConnections(listener, sockPath)

    // 4. Apply seccomp filter BEFORE spawning child
    // Seccomp filters are inherited across fork/execve, so both
    // the helper and agent get the same restrictions.
    if err := applySeccompFilter(); err != nil {
        return fmt.Errorf("failed to apply seccomp: %w", err)
    }

    // 5. Drop privileges BEFORE spawning child
    if err := syscall.Setgid(dropGID); err != nil {
        return fmt.Errorf("failed to setgid: %w", err)
    }
    if err := syscall.Setuid(dropUID); err != nil {
        return fmt.Errorf("failed to setuid: %w", err)
    }

    // 6. Start agent as CHILD process (not Exec!)
    // We must stay alive to run the forwarder goroutine.
    // exec.Command does LookPath internally when needed.
    cmd := exec.Command(execCmd[0], execCmd[1:]...)
    cmd.Env = os.Environ()
    cmd.Stdin = os.Stdin
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr

    if err := cmd.Start(); err != nil {
        return fmt.Errorf("failed to start agent: %w", err)
    }

    // 7. Wait for agent to exit, then clean up
    agentErr := cmd.Wait()
    listener.Close() // This will cause forwardConnections to exit
    return agentErr
}

func forwardConnections(listener net.Listener, sockPath string) {
    for {
        tcpConn, err := listener.Accept()
        if err != nil {
            // Exit when listener is closed (avoids 100% CPU spin)
            // The only expected error is from Close(), so just return
            return
        }
        go func(tc net.Conn) {
            defer tc.Close()

            // Dial Unix socket for this connection
            unixConn, err := net.Dial("unix", sockPath)
            if err != nil {
                return
            }
            defer unixConn.Close()

            // Bidirectional copy
            done := make(chan struct{})
            go func() {
                io.Copy(unixConn, tc)
                done <- struct{}{}
            }()
            io.Copy(tc, unixConn)
            <-done
        }(tcpConn)
    }
}
```

### Seccomp Filter (Default-Deny)

Allows AF_UNIX socket creation since we use per-connection dialing. Security comes from the filesystem view (only `/run/warden/` is accessible):

```go
func applySeccompFilter() error {
    filter, err := seccomp.NewFilter(seccomp.ActKillProcess)
    if err != nil {
        return err
    }

    // Allow essential syscalls
    essentialSyscalls := []string{
        // Process lifecycle
        "exit", "exit_group", "rt_sigreturn",
        // Memory management
        "brk", "mmap", "munmap", "mprotect", "mremap",
        // File I/O
        "open", "read", "write", "close", "fstat", "lseek", "openat",
        "readv", "writev", "pread64", "pwrite64",
        // Directories
        "getdents64", "getcwd", "chdir", "fchdir",
        // File metadata (including newer stat variants)
        "stat", "lstat", "newfstatat", "statx", "access", "faccessat", "readlink",
        // Descriptors
        "dup", "dup2", "dup3", "pipe", "pipe2", "fcntl",
        // Polling/events
        "poll", "ppoll", "select", "pselect6",
        "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
        "eventfd2",
        // Go runtime
        "futex", "get_robust_list", "set_robust_list",
        "clone", "clone3", "wait4", "execve",
        // Time
        "clock_gettime", "clock_getres", "gettimeofday", "nanosleep",
        // Identity
        "getpid", "gettid", "getuid", "getgid", "geteuid", "getegid",
        "getgroups", "setuid", "setgid",
        // Misc
        "arch_prctl", "prctl", "set_tid_address",
        "rt_sigaction", "rt_sigprocmask", "sigaltstack",
        "getrandom", "uname",
    }

    for _, name := range essentialSyscalls {
        num, err := seccomp.GetSyscallFromName(name)
        if err != nil {
            continue // Skip unknown syscalls (arch-specific)
        }
        filter.AddRule(num, seccomp.ActAllow)
    }

    // Network syscalls - allow TCP and Unix sockets
    // Security: namespace has no external interfaces, only /run/warden/ unix socket accessible
    filter.AddRuleConditional(unix.SYS_SOCKET, seccomp.ActAllow,
        seccomp.Condition{Arg: 0, Op: seccomp.CompareEqual, Value: unix.AF_INET},
    )
    filter.AddRuleConditional(unix.SYS_SOCKET, seccomp.ActAllow,
        seccomp.Condition{Arg: 0, Op: seccomp.CompareEqual, Value: unix.AF_UNIX},
    )
    // AF_UNIX is safe because the only visible Unix socket path in the sandbox
    // is /run/warden/proxy.sock. We do NOT mount /run or /var/run from the host,
    // so the agent cannot connect to /var/run/docker.sock or similar.

    // Block raw sockets (defense in depth, though useless without network)
    // AF_INET + SOCK_RAW is blocked by not having a permissive rule

    // Allow other network syscalls
    for _, name := range []string{
        "connect", "bind", "listen", "accept", "accept4",
        "getsockname", "getpeername", "getsockopt", "setsockopt",
        "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown",
    } {
        num, err := seccomp.GetSyscallFromName(name)
        if err != nil {
            continue // Skip unknown syscalls (arch-specific)
        }
        filter.AddRule(num, seccomp.ActAllow)
    }

    return filter.Load()
}
```

### Bwrap Invocation

**Fixed:** Cleanup tied to Process lifetime, not `defer` in Start:

```go
func (b *BubblewrapBackend) Start(ctx context.Context, cfg *Config) (*Process, error) {
    // Setup socket directory with restricted permissions
    sockDir := filepath.Join(os.TempDir(), fmt.Sprintf("warden-%d", os.Getpid()))
    if err := os.MkdirAll(sockDir, 0700); err != nil {
        return nil, fmt.Errorf("failed to create socket dir: %w", err)
    }
    sockPath := filepath.Join(sockDir, "proxy.sock")

    // Start bridge
    bridge, err := startBridge(sockPath, cfg.ProxyAddr)
    if err != nil {
        os.RemoveAll(sockDir)
        return nil, fmt.Errorf("failed to start bridge: %w", err)
    }

    // Find our own binary for re-exec inside sandbox
    wardenBin, err := os.Executable()
    if err != nil {
        bridge.Close()
        os.RemoveAll(sockDir)
        return nil, fmt.Errorf("failed to find warden binary: %w", err)
    }

    // Build bwrap args
    args := []string{
        "--unshare-net",
        "--unshare-pid",
        "--unshare-uts",   // Hostname isolation
        "--unshare-ipc",   // IPC isolation
        "--die-with-parent",
        "--dev", "/dev",
        "--proc", "/proc",
    }

    // System paths (read-only)
    for _, p := range []string{"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"} {
        if _, err := os.Stat(p); err == nil {
            args = append(args, "--ro-bind", p, p)
        }
    }

    // Home directory (needed for many tools, but read-only)
    home, _ := os.UserHomeDir()
    if home != "" {
        args = append(args, "--ro-bind", home, home)
    }

    // Denied read paths - use tmpfs to hide them
    // NOTE: Globs not supported on Linux - must be literal paths
    for _, p := range cfg.DeniedReadPaths {
        expanded := expandPath(p)
        if isGlob(expanded) {
            return nil, fmt.Errorf("globs in denied_read_paths not supported on Linux: %s", p)
        }
        if _, err := os.Stat(expanded); err == nil {
            args = append(args, "--tmpfs", expanded)
        }
    }

    // Allowed write paths - bind read-write
    // NOTE: Globs not supported on Linux - must be literal paths
    for _, p := range cfg.AllowedWritePaths {
        expanded := expandPath(p)
        if isGlob(expanded) {
            return nil, fmt.Errorf("globs in allowed_write_paths not supported on Linux: %s", p)
        }
        args = append(args, "--bind", expanded, expanded)
    }

    // Tmp directory (writable)
    args = append(args, "--tmpfs", "/tmp")

    // Socket directory - ONLY place with Unix socket access
    args = append(args, "--bind", sockDir, "/run/warden")

    // Warden binary
    args = append(args, "--ro-bind", wardenBin, "/usr/bin/warden")

    // Working directory (default to $HOME if not specified)
    workDir := cfg.WorkingDir
    if workDir == "" {
        workDir = home
    }
    if workDir != "" {
        args = append(args, "--chdir", workDir)
    }

    // Build netns command
    netnsArgs := []string{
        "/usr/bin/warden", "netns",
        "--sock", "/run/warden/proxy.sock",
        "--listen", "127.0.0.1:3128",
        "--drop-to", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
    }
    if cfg.EnablePTY {
        netnsArgs = append(netnsArgs, "--enable-pty")
    }
    netnsArgs = append(netnsArgs, "--exec", cfg.Command[0], "--")
    netnsArgs = append(netnsArgs, cfg.Command[1:]...)

    args = append(args, "--")
    args = append(args, netnsArgs...)

    if cfg.Debug {
        log.Printf("bwrap command: bwrap %s", strings.Join(args, " "))
    }

    cmd := exec.CommandContext(ctx, "bwrap", args...)
    cmd.Env = append(cfg.Env,
        "HTTP_PROXY=http://127.0.0.1:3128",
        "HTTPS_PROXY=http://127.0.0.1:3128",
    )
    cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

    stdin, _ := cmd.StdinPipe()
    stdout, _ := cmd.StdoutPipe()
    stderr, _ := cmd.StderrPipe()

    if err := cmd.Start(); err != nil {
        bridge.Close()
        os.RemoveAll(sockDir)
        return nil, fmt.Errorf("failed to start bwrap: %w", err)
    }

    return &Process{
        PID:    cmd.Process.Pid,
        Stdin:  stdin,
        Stdout: stdout,
        Stderr: stderr,
        Wait: func() error {
            err := cmd.Wait()
            bridge.Close()
            os.RemoveAll(sockDir)
            return err
        },
    }, nil
}
```

### Linux-Specific Notes

**Filesystem layout:** The sandbox sees a modified filesystem view:
- System paths (`/usr`, `/lib`, `/bin`, `/etc`) are read-only bind mounts
- Home directory is read-only by default
- Denied read paths are hidden via `--tmpfs` overlays (appear as empty directories)
- Allowed write paths are bind-mounted read-write
- `/tmp` is a fresh tmpfs (not shared with host)
- `/run/warden/` contains the Unix socket for proxy communication
- `/proc` and `/dev` are minimal synthetic mounts

**Glob support:** Not available. Bwrap uses literal paths for `--bind` and `--tmpfs`. Globs in config are rejected with a clear error.

**PTY support:** Requires additional handling in netns helper (allocate PTY, set up terminal).

**Process group:** `Setpgid: true` ensures the whole sandbox can be killed on context cancel.

**Working directory:** `WorkingDir` must be inside one of the mounted paths (`$HOME`, system dirs, or an allowed write path). If `WorkingDir` points to a path not in the sandbox's mount tree, bwrap will fail to start. Defaults to `$HOME` if not specified.

---

## Glob Pattern Handling

### OS-Specific Limitations

| Feature | macOS (Seatbelt) | Linux (Bubblewrap) |
|---------|------------------|-------------------|
| Literal paths | ✓ | ✓ |
| Single `*` glob | ✓ (via regex) | ✗ (error) |
| Double `**` glob | ✓ in deny rules | ✗ (error) |
| Regex patterns | ✓ (native SBPL) | ✗ |

Document this clearly in user-facing docs and error messages.

### Safety Requirements

Globs in **allow rules** (AllowedWritePaths) are more dangerous than deny rules:

| Rule Type | Single `*` | Double `**` | Min Depth |
|-----------|-----------|-------------|-----------|
| Deny read | Allowed | Allowed | None |
| Allow write | Allowed | Blocked | 2 directories |

### Implementation

```go
func processPath(path string, isAllowRule bool, targetOS string) (filter string, isRegex bool, err error) {
    expanded := expandHome(path)

    // Linux doesn't support globs
    if targetOS == "linux" && isGlob(expanded) {
        return "", false, fmt.Errorf("globs not supported on Linux: %s", path)
    }

    // Validate safety
    if err := validatePathSafety(expanded, isAllowRule); err != nil {
        return "", false, err
    }

    // Literal path
    if !isGlob(expanded) {
        resolved, _ := filepath.Abs(expanded)
        return resolved, false, nil
    }

    // Glob → regex (macOS only)
    regex, err := safeGlobToRegex(expanded)
    return regex, true, err
}

func validatePathSafety(path string, isAllowRule bool) error {
    // Block path traversal
    if strings.Contains(path, "..") {
        return fmt.Errorf("path traversal not allowed: %s", path)
    }

    // Block root wildcards
    if path == "/*" || path == "/**" {
        return fmt.Errorf("root wildcard not allowed: %s", path)
    }

    // Block regex injection
    suspicious := []string{"(?", "\\d", "\\w", "{", "}"}
    for _, s := range suspicious {
        if strings.Contains(path, s) {
            return fmt.Errorf("suspicious pattern: %s", path)
        }
    }

    // Extra restrictions for allow rules
    if isAllowRule && isGlob(path) {
        if strings.Contains(path, "**") {
            return fmt.Errorf("** not allowed in write paths: %s", path)
        }

        prefix := extractLiteralPrefix(path)
        if strings.Count(prefix, "/") < 2 {
            return fmt.Errorf("allow glob too broad, need at least 2 directory levels: %s", path)
        }

        if isSensitivePath(prefix) {
            return fmt.Errorf("cannot allow writes to sensitive path: %s", path)
        }
    }

    return nil
}

// isSensitivePath blocks writes to dangerous locations even with globs
func isSensitivePath(path string) bool {
    sensitive := []string{
        "/", "/etc", "/usr", "/var", "/bin", "/sbin", "/lib",
        "/root", "/home",
    }
    home, _ := os.UserHomeDir()
    if home != "" {
        sensitive = append(sensitive, home,
            filepath.Join(home, ".ssh"),
            filepath.Join(home, ".aws"),
            filepath.Join(home, ".gnupg"),
            filepath.Join(home, ".kube"),
        )
    }

    for _, s := range sensitive {
        if path == s || strings.HasPrefix(path, s+"/") {
            return true
        }
    }
    return false
}

func safeGlobToRegex(pattern string) (string, error) {
    var buf strings.Builder
    buf.WriteString("^")

    for i := 0; i < len(pattern); i++ {
        switch pattern[i] {
        case '*':
            if i+1 < len(pattern) && pattern[i+1] == '*' {
                buf.WriteString(".*")
                i++
            } else {
                buf.WriteString("[^/]*")
            }
        case '?':
            buf.WriteString("[^/]")
        case '.', '+', '^', '$', '|', '(', ')', '[', ']', '\\':
            buf.WriteByte('\\')
            buf.WriteByte(pattern[i])
        default:
            buf.WriteByte(pattern[i])
        }
    }

    buf.WriteString("$")
    return buf.String(), nil
}
```

---

## Migration from srt

Existing veil configs work unchanged:

```yaml
# Before (srt)
sandbox:
  backend: srt    # or anthropic

# After (warden)
sandbox:
  backend: auto   # Uses native implementation

# Or keep using srt
sandbox:
  backend: srt    # Still works if srt installed
```

---

## Testing Strategy

### Unit Tests

- **Profile generation:** Golden tests comparing generated SBPL against expected output for various configs
- **Bwrap args:** Golden tests for bwrap command-line construction
- **Glob validation:** Table-driven tests for valid/invalid patterns, edge cases
- **Path safety:** Tests for traversal attacks, sensitive path detection
- **Regex escaping:** Tests for special characters `[`, `]`, `+`, `^`, etc.

### Integration Tests

Actually spawn sandboxed processes and verify:

```go
func TestFilesystemIsolation(t *testing.T) {
    // Try to read ~/.ssh/id_rsa → should fail
    // Try to write /etc/passwd → should fail
    // Try to write to allowed path → should succeed
}

func TestNetworkIsolation(t *testing.T) {
    // Start a test HTTP server on host
    // Try direct curl to external site → should fail
    // Try curl through proxy to test server → should succeed
}
```

### Escape Tests

- **Symlink attack:** Create symlink in allowed write dir pointing to denied path
- **Path traversal:** `open("/tmp/allowed/../../../etc/shadow")`
- **Unix socket attack:** Try to connect to `/var/run/docker.sock` (shouldn't be visible)
- **Raw socket:** Try to create raw socket (should fail or be useless)
- **Network bypass:** Try direct TCP to external IP (should have no route)

### Platform-Specific Tests

- **macOS:** Test mach-lookup restrictions (shouldn't be able to contact arbitrary services)
- **Linux:** Test seccomp filter (blocked syscalls should fail)
- **Both:** PTY tests when `enable_pty: true`

---

## Future Enhancements

- **`cmd/warden/` standalone CLI** - `warden exec --config warden.yaml -- python agent.py`
- **Resource limits** - cgroups v2 on Linux for CPU/memory limits
- **User namespaces** - `--unshare-user` for rootless operation
- **Seccomp audit mode** - Log blocked syscalls instead of killing (for debugging)
- **Config presets** - `mode: strict` vs `mode: dev` with sensible defaults
- **Observability** - Audit log of denied operations
- **More backends** - gVisor, Firecracker for stronger isolation
