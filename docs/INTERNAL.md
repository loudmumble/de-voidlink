# DE-VoidLink — Internal Developer Guide

> **Classification**: Internal use only. This document describes the full architecture, cryptographic protocols, evasion capabilities, and payload swap points of the DE-VoidLink adversary simulation framework.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Zig Beacon (Implant Simulator)](#2-zig-beacon-implant-simulator)
3. [Go C2 Server](#3-go-c2-server)
4. [VoidStream Protocol](#4-voidstream-protocol)
5. [Camouflage System](#5-camouflage-system)
6. [Cadence Profiles](#6-cadence-profiles)
7. [Arsenal Plugin System](#7-arsenal-plugin-system)
8. [Evasion Capabilities](#8-evasion-capabilities)
9. [Detection Rules](#9-detection-rules)
10. [Payload Swap Points](#10-payload-swap-points)
11. [Data Flow Diagrams](#11-data-flow-diagrams)
12. [Security Architecture Decisions](#12-security-architecture-decisions)

---

## 1. Architecture Overview

DE-VoidLink is a three-component adversary simulation framework that replicates the exact techniques of the [VoidLink](https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/) malware framework. Each component mirrors the real malware's technology stack:

```
┌─────────────────────────────────────────────────────────────────┐
│                    DE-VoidLink Architecture                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    VoidStream     ┌──────────────────┐    │
│  │   Zig Beacon     │◄───(AES-256-GCM)──►│   Go C2 Server   │    │
│  │  (phantom-beacon)│    + Camouflage   │   (c2server)     │    │
│  │                  │                   │                  │    │
│  │  • Direct syscalls│    HTTP/TCP      │  • Session mgmt  │    │
│  │  • Process masq.  │◄──────────────►│  • Kill switch   │    │
│  │  • EDR detection  │                  │  • Stage serving │    │
│  │  • Plugin loader  │                  │  • Compile sim   │    │
│  └────────┬─────────┘                   └──────────────────┘    │
│           │                                                     │
│           │ ELF .o loading                                      │
│           ▼                                                     │
│  ┌─────────────────┐                                            │
│  │  C Arsenal       │                                           │
│  │  (plugin .o)     │                                           │
│  │                  │                                           │
│  │  • recon.o       │                                           │
│  │  • cred_harvest.o│                                           │
│  │  • persist.o     │                                           │
│  └──────────────────┘                                           │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Detection Rules (YARA / Sigma / Aegis)                   │   │
│  │  For validating defensive tool coverage                    │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Component Summary

| Component | Language | Binary | Lines of Code | Role |
|-----------|----------|--------|---------------|------|
| `core/` | Zig | `build/phantom-beacon` | ~1,900 | Implant simulator — direct Linux syscalls, VoidStream decryption, process masquerade, EDR detection, ELF plugin loading |
| `c2/` | Go | `build/c2server` | ~1,000 | Mock C2 server — VoidStream encryption, HTTP camouflage (5 modes), session management, adaptive cadence |
| `arsenal/` | C | `build/arsenal/*.o` | ~500 | Relocatable ELF plugins — recon, credential path enumeration, persistence vector enumeration |
| `detection/` | YARA/Sigma/JSON | — | ~400 | Static (YARA), behavioral (Sigma), and network (Aegis) detection rules |

### Source File Map

```
core/src/
├── main.zig           Entry point: CLI parsing, safety checks, syscall sequence, beacon loop
├── beacon.zig         C2 heartbeat loop, handshake, adaptive timing, raw TCP HTTP
├── config.zig         Constants: magic values, syscall numbers, timing profiles, C2 endpoints
├── syscall.zig        Direct Linux syscall wrappers (NO libc): fork, socket, connect, memfd_create, etc.
├── voidstream.zig     VoidStream protocol: AES-256-GCM decryption, camouflage unwrapping
├── evasion.zig        EDR/AV process scanning via /proc enumeration, debugger detection
├── masquerade.zig     Process name masquerade via prctl(PR_SET_NAME)
└── plugin_loader.zig  ELF ET_REL relocatable object loader with relocation application

c2/
├── cmd/c2server/main.go            CLI entry point with flag parsing
└── internal/
    ├── server/server.go            HTTP server, session store, lifecycle management
    ├── handler/handler.go          All VoidLink C2 endpoint handlers
    ├── protocol/voidstream.go      VoidStream AES-256-GCM encryption
    ├── camouflage/camouflage.go    HTTP response camouflage (PNG/JS/CSS/HTML/JSON)
    └── cadence/cadence.go          Adaptive beacon timing (VoidLink + AI-cadence modes)

arsenal/
├── include/plugin_api.h    Plugin C ABI definition (SyscallTable, PluginContext, macros)
├── recon.c                 System reconnaissance via uname/getuid/getgid syscalls
├── cred_harvest.c          Credential path existence checking (21 paths)
├── persist.c               Persistence vector writeability checking (19 locations)
└── Makefile                Compile plugins as ET_REL relocatable objects

detection/
├── yara/                   4 rule files (14 rules total) — static artifact detection
├── sigma/                  3 rule files (7 rules total) — behavioral correlation
├── aegis/                  1 JSON profile — network cadence analysis
└── malscope/               3 JSON profiles — behavioral, IOC, and ELF indicator detection
```

---

## 2. Zig Beacon (Implant Simulator)

### 2.1 Execution Flow

The beacon follows this exact sequence on startup:

```
1. Parse CLI arguments (--c2-addr, --c2-port, --dry-run, --live, etc.)
2. Safety check: PHANTOM_LINK_SAFETY env var must == "1" for live mode
3. Startup banner (JSON structured log)
4. Process masquerade via prctl(PR_SET_NAME) — mimics kernel worker threads
5. Security product enumeration — scan /proc for EDR/AV processes
6. VoidLink syscall fingerprint sequence (THE detection signal):
   fork(57) → prctl(157) → socket(41) → connect(42) → recvfrom(45)
   → memfd_create(319) → write(1) → [execveat(322) LOGGED ONLY]
7. C2 handshake (POST /api/v2/handshake)
8. Beacon loop (GET /api/v2/heartbeat at adaptive intervals)
9. Exit
```

### 2.2 Syscall Interface (`syscall.zig`)

All system calls are invoked directly through `std.os.linux.syscallN()` — **no libc is linked**. This mirrors VoidLink's exact approach for avoiding userland hooking by EDR tools.

Key wrappers:

| Function | Syscall # | Purpose |
|----------|-----------|---------|
| `sys_fork()` | 57 | Process forking |
| `sys_prctl(option, arg)` | 157 | Process name masquerade |
| `sys_socket(domain, type, proto)` | 41 | TCP socket creation |
| `sys_connect(fd, addr, len)` | 42 | C2 connection |
| `sys_recvfrom(fd, buf, len, flags)` | 45 | Data reception |
| `sys_memfd_create(name, flags)` | 319 | Anonymous in-memory file |
| `sys_write_syscall(fd, buf, count)` | 1 | Write to fd/memfd |
| `sys_mmap(addr, len, prot, flags, fd, off)` | 9 | Memory mapping (plugin loader) |
| `sys_mprotect(addr, len, prot)` | 10 | Memory protection (RX for code) |
| `sys_openat(dirfd, path, flags, mode)` | 257 | File opening (plugin loader) |

### 2.3 The VoidLink Syscall Fingerprint

In live mode, `main.zig:executeVoidLinkSequence()` forks a child process that executes the exact syscall chain that identifies VoidLink:

```zig
// CHILD PROCESS (childSequence):
1. prctl(PR_SET_NAME, "[kworker/0:0]")    // Masquerade as kernel thread
2. socket(AF_INET, SOCK_STREAM, 0)        // Create TCP socket
3. connect(sock, c2_addr:c2_port)          // Connect to C2
4. recvfrom(sock, buf, 1024, 0)            // Receive stage payload
5. memfd_create("", MFD_CLOEXEC)           // Create anonymous memory file
6. write(memfd, payload)                   // Write payload to memfd
7. execveat — LOGGED ONLY, NEVER EXECUTED  // Safety: simulation stops here
```

**Critical safety note**: `execveat` is never called. The beacon logs the syscall number but explicitly skips execution. The comment in `main.zig:196` reads: `"simulation safety -- never execute in simulator"`.

In dry-run mode, `dryRunSequence()` logs each syscall step without executing any of them.

### 2.4 Process Masquerade (`masquerade.zig`)

The beacon disguises its process name using `prctl(PR_SET_NAME)` to appear as a kernel worker thread in `ps`/`top` output. Names are selected deterministically from a pool matching real VoidLink samples:

```
[kworker/0:0]    [kworker/0:1]    [kworker/u8:0]
migration/0      watchdog/0       rcu_sched
```

Selection formula: `MASQUERADE_NAMES[seed % len]` where seed is the PID.

The name is truncated to 15 bytes + null terminator (kernel `TASK_COMM_LEN` limit).

### 2.5 EDR Detection (`evasion.zig`)

The beacon scans `/proc` to enumerate running processes and matches against 12 known security products:

```
falcon-sensor    SentinelAgent    cbagentd        falco
sysdig           wazuh-agent      ossec           osqueryd
auditd           clamd            AliYunDun       frida-server
```

Detection results feed into the timing profile selector:
- **0 products found** → risk_score=0, aggressive profile (4096ms base, 20% jitter)
- **1-2 products found** → risk_score=50, paranoid profile (1024ms base, 30% jitter)
- **3+ products found** → risk_score=90, paranoid profile

Additionally, `checkDebugger()` reads `/proc/self/status` to detect `TracerPid != 0`, indicating an attached debugger (ptrace).

---

## 3. Go C2 Server

### 3.1 Server Architecture (`server.go`)

The C2 server is a standard Go `net/http` server with:

- **Localhost binding by default** (`127.0.0.1:8080`) — non-localhost triggers a warning
- **Max runtime auto-shutdown** — configurable via `--max-runtime` (default 300s)
- **Graceful shutdown** via `sync.Once` pattern, triggered by:
  - OS signal (SIGINT/SIGTERM)
  - Max runtime timer
  - Kill switch endpoint (`POST /api/v2/kill`)
- **Session store** — thread-safe `sync.RWMutex`-protected `map[string]*Session`
- **Stale session cleanup** — goroutine removes sessions not seen in 5 minutes

### 3.2 API Endpoints (`handler.go`)

| Method | Path | Handler | Description |
|--------|------|---------|-------------|
| POST | `/api/v2/handshake` | `handleHandshake` | Client registration. Accepts hostname/OS/kernel/arch/EDR info. Returns VoidStream-encrypted session config wrapped in camouflage. |
| POST | `/api/v2/sync` | `handleSync` | Task synchronization. Accepts task results, returns pending tasks. Encrypted + camouflaged. |
| GET | `/api/v2/heartbeat` | `handleHeartbeat` | Keep-alive. Requires `X-Session-ID` header. Returns plain JSON. |
| POST | `/compile` | `handleCompile` | **⚡ PAYLOAD SWAP POINT** — SRC (Serverside Rootkit Compilation) simulation. Returns 256 benign placeholder bytes. |
| GET | `/stage1.bin` | `handleStage1` | **⚡ PAYLOAD SWAP POINT** — Stage 1 download. Returns 4096-byte benign ELF placeholder. |
| GET | `/implant.bin` | `handleImplant` | **⚡ PAYLOAD SWAP POINT** — Implant download. Returns 8192-byte benign ELF placeholder. |
| POST | `/api/v2/kill` | `handleKill` | Safety kill switch. Initiates graceful shutdown. |

### 3.3 Session Management

Sessions are created during handshake with UUIDv4 IDs (crypto/rand). Each session tracks:
- Hostname, OS, Kernel, Arch
- Connected timestamp, last-seen timestamp
- Heartbeat count
- Cadence profile assignment

Sessions are validated on every sync/heartbeat request. Invalid session IDs receive HTTP 401.

---

## 4. VoidStream Protocol

VoidStream is the encryption layer for C2 communication, matching VoidLink's exact wire format.

### 4.1 Key Derivation

```
SharedSecret = "de-voidlink-test-key-do-not-use"  (hardcoded for simulation)
AES_Key = SHA-256(SharedSecret)                    → 32 bytes (AES-256)
```

Both the Go server (`protocol/voidstream.go`) and Zig beacon (`voidstream.zig`) derive the key identically.

**⚡ SWAP POINT**: For operational use, replace `SharedSecret` with a per-session negotiated key or embed a key exchange protocol. Files to modify:
- `c2/internal/protocol/voidstream.go:15` — `SharedSecret` constant
- `core/src/voidstream.zig:7` — `SHARED_SECRET` constant

### 4.2 Wire Format

```
┌─────────────────────────────────────────────────────────┐
│  4 bytes     │  12 bytes  │  N bytes     │  16 bytes    │
│  BE length   │  Nonce     │  Ciphertext  │  GCM Tag     │
│  (uint32)    │  (random)  │  (payload)   │  (auth tag)  │
└─────────────────────────────────────────────────────────┘
  ◄─────────── length field covers this entire span ──────►
```

**Length field**: Big-endian uint32 encoding `12 + len(ciphertext) + 16`.

### 4.3 Encryption (Go Server → Beacon)

```go
// protocol/voidstream.go:Encrypt()
1. key = SHA-256(SharedSecret)
2. nonce = crypto/rand(12 bytes)
3. sealed = AES-256-GCM.Seal(nonce, plaintext, nil)  // Go appends tag
4. msg = [BE_uint32(len(nonce + sealed))] || nonce || sealed
```

### 4.4 Decryption (Beacon → Plaintext)

```zig
// voidstream.zig:decrypt()
1. Parse 4-byte BE length prefix
2. Extract nonce (bytes 4..16)
3. Split remaining into ciphertext + tag (last 16 bytes)
4. key = SHA-256(SHARED_SECRET)
5. plaintext = AES-256-GCM.decrypt(ciphertext, tag, nonce, key)
```

### 4.5 XOR Encoding

A secondary encoding layer using single-byte XOR (key `0xAA`) is available for config blobs. Defined in both Go and Zig but primarily used for future extensibility:

```
encoded[i] = data[i] ^ 0xAA
```

---

## 5. Camouflage System

The camouflage system wraps encrypted VoidStream payloads in legitimate-looking HTTP response bodies. The C2 server rotates through 5 modes using an atomic counter (round-robin).

### 5.1 Camouflage Modes

| Mode | Content-Type | Wrapper Format | Extraction Marker |
|------|-------------|----------------|-------------------|
| **PNG** | `image/png` | Valid 1×1 RGBA PNG, payload in IDAT chunk | Parse PNG chunks, extract IDAT data |
| **JavaScript** | `application/javascript` | `var _0x=["<base64>"];` | Extract between `["` and `"];` |
| **CSS** | `text/css` | `/* font-data: <base64> */\nbody { ... }` | Extract between `font-data: ` and ` */` |
| **HTML** | `text/html` | `<!DOCTYPE html>...<!-- <base64> -->...` | Extract between `<!-- ` and ` -->` |
| **API JSON** | `application/json` | `{"data":"<base64>","status":"ok"}` | Extract between `"data":"` and `","status"` |

### 5.2 PNG Camouflage (Deep Dive)

The PNG wrapper generates a structurally valid PNG file:

```
[8-byte PNG signature]
[IHDR chunk: 1×1 pixel, 8-bit RGBA, CRC32]
[IDAT chunk: encrypted payload as chunk data, CRC32]
[IEND chunk: empty, CRC32]
```

CRC32 is computed per PNG spec (IEEE polynomial over chunk type + data). This means the file passes basic PNG validation tools, though the IDAT data is not valid zlib-compressed image data.

### 5.3 Full Pipeline

```
Server side:   plaintext → AES-256-GCM encrypt → camouflage wrap → HTTP response
Beacon side:   HTTP response → detect Content-Type → unwrap camouflage → AES-256-GCM decrypt → plaintext
```

The beacon's `voidstream.zig:processResponse()` chains both steps. If VoidStream decryption fails, the beacon falls back to parsing the raw body as plain JSON.

---

## 6. Cadence Profiles

### 6.1 VoidLink Mode (`--mode=voidlink`)

Risk-based adaptive timing matching real VoidLink beaconing behavior.

| Profile | Trigger | Base Interval | Jitter | Formula |
|---------|---------|---------------|--------|---------|
| **Aggressive** | No EDR detected | 4096 ms | ±20% | `actual = base + random(-0.2, +0.2) * base` |
| **Paranoid** | EDR detected | 1024 ms | ±30% | `actual = base + random(-0.3, +0.3) * base` |

Floor: 50ms minimum to prevent spin-looping.

Profile is selected at handshake time based on the `edr_detected` field in the registration request.

### 6.2 AI-Cadence Mode (`--mode=ai-cadence`)

Mimics LLM autoregressive token generation timing to test detection of AI-traffic masquerading:

```
Pattern: [think pause] → [burst of N tokens] → [think pause] → [burst] → ...

Think pause:  500–2000 ms (uniform random)
Token burst:  50–150 ms per token, 5–20 tokens per burst
```

This generates traffic that looks like a human interacting with an AI chatbot, making it harder for pattern-based detectors to flag.

### 6.3 Implementation Details

- **Zig beacon** (`beacon.zig:computeInterval`): Uses timestamp low bits as cheap entropy for jitter. No CSPRNG needed for timing.
- **Go C2** (`cadence.go:NextInterval`): Uses `math/rand` with nanosecond seed. Reports interval in heartbeat metadata.

---

## 7. Arsenal Plugin System

### 7.1 Plugin ABI (`plugin_api.h`)

Plugins are compiled as **ELF ET_REL (relocatable) objects** — not shared libraries. This mirrors VoidLink's BOF (Beacon Object File)-style loading.

**Compilation flags**: `-c -fPIC -fno-stack-protector -nostdlib -ffreestanding`

Every plugin must export 4 symbols:

```c
PluginInfo* plugin_info(void);                // Metadata (name, version, capabilities)
int plugin_init(PluginContext *ctx);           // One-time setup, return 0 on success
int plugin_exec(PluginContext *ctx);           // Main logic, write results to ctx->output
int plugin_cleanup(PluginContext *ctx);        // Teardown
```

### 7.2 PluginContext Structure

```c
typedef struct {
    ExecMode     mode;        // 0=normal, 1=dry_run, 2=verbose
    OutputBuffer output;      // {data*, capacity, length} — 64KB buffer provided by loader
    SyscallTable *syscalls;   // Direct syscall dispatch (see below)
    const char   *c2_addr;    // C2 server address (for network plugins)
    uint16_t      c2_port;    // C2 server port
    uint32_t      flags;      // Reserved
} PluginContext;
```

### 7.3 SyscallTable Dispatch

The plugin loader provides a `SyscallTable` struct with function pointers for direct syscall invocation. Each function takes the syscall number as the first argument:

```c
typedef struct {
    long (*syscall0)(long nr);
    long (*syscall1)(long nr, long a1);
    long (*syscall2)(long nr, long a1, long a2);
    long (*syscall3)(long nr, long a1, long a2, long a3);
    long (*syscall4)(long nr, long a1, long a2, long a3, long a4);
    long (*syscall6)(long nr, long a1, long a2, long a3, long a4, long a5, long a6);
} SyscallTable;
```

The Zig side (`plugin_loader.zig`) implements these using inline assembly:

```zig
fn wrap_syscall3(nr: isize, a1: isize, a2: isize, a3: isize) callconv(.c) isize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> isize),
        : [number] "{rax}" (nr),
          [arg1] "{rdi}" (a1),
          [arg2] "{rsi}" (a2),
          [arg3] "{rdx}" (a3),
        : "rcx", "r11", "memory"
    );
}
```

### 7.4 ELF Relocatable Object Loader (`plugin_loader.zig`)

The loader performs a full ELF relocation pipeline:

```
Step 1: Read .o file via sys_openat + sys_read into mmap'd buffer
Step 2: Validate ELF header (magic, e_type == ET_REL)
Step 3: Parse section headers — categorize into code/rodata/data zones
Step 4: Allocate execution memory via sys_mmap (RW initially)
Step 5: Copy section data into zones at computed addresses
Step 6: Resolve symbols + apply relocations:
        - R_X86_64_64     → S + A (64-bit absolute)
        - R_X86_64_PC32   → S + A - P (32-bit PC-relative)
        - R_X86_64_PLT32  → S + A - P (32-bit PC-relative, same as PC32)
        - R_X86_64_32S    → S + A (32-bit signed)
Step 7: Set memory protections:
        - Code zone  → PROT_READ | PROT_EXEC
        - Rodata zone → PROT_READ
        - Data zone  → PROT_READ | PROT_WRITE (unchanged)
Step 8: Find plugin_info/plugin_init/plugin_exec/plugin_cleanup by name
Step 9: Call init → exec → cleanup, collect output
```

**External symbol resolution**: Only `memcpy` is resolved (via a custom `plugin_memcpy` implementation). Unknown externals are skipped with a warning.

### 7.5 Shipped Plugins

| Plugin | File | Capabilities | What It Does (Benign) |
|--------|------|-------------|----------------------|
| **recon** | `recon.c` | `CAP_FILESYSTEM` | Calls `uname(2)` and `getuid(2)`/`getgid(2)` via SyscallTable. Reports hostname, kernel, arch, OS, UID, GID as JSON. |
| **cred_harvest** | `cred_harvest.c` | `CAP_FILESYSTEM`, `CAP_STEALTH` | Checks existence of 22 credential paths (AWS, GCP, Azure, SSH, K8s, Docker, browser) via `openat(O_PATH)`. Reports which paths exist. Does NOT read contents. |
| **persist** | `persist.c` | `CAP_FILESYSTEM`, `CAP_PRIVILEGED` | Checks writeability of 21 persistence locations (cron, systemd, shell profiles, LD_PRELOAD, init scripts, SSH authorized_keys, kernel modules). Reports which are writable. Does NOT modify any files. Maps to MITRE ATT&CK technique IDs. |

**⚡ PLUGIN SWAP POINTS**: Each plugin's `plugin_exec()` function is a swap point. To add operational capabilities:
- **recon.c**: Replace benign uname/getuid with actual data collection and exfiltration
- **cred_harvest.c**: Replace `openat(O_PATH)` existence checks with actual file reads
- **persist.c**: Replace `access(W_OK)` checks with actual persistence installation

---

## 8. Evasion Capabilities

### 8.1 Direct Syscall Interface

The entire beacon uses direct Linux syscalls via Zig's `std.os.linux.syscallN()`. No libc is linked. This bypasses:
- `LD_PRELOAD` hooking
- ptrace-based userland syscall interception
- LIEF/eBPF user-space function tracing

### 8.2 Process Name Masquerade

Uses `prctl(PR_SET_NAME)` to change the process name to kernel worker thread names. After masquerade, the beacon appears as `[kworker/0:0]` in `ps`, `top`, `/proc/<pid>/comm`.

### 8.3 In-Memory Execution

The `memfd_create → write → [execveat]` pattern creates anonymous file descriptors backed by memory. In the real malware, this enables fileless execution — the payload never touches disk. In DE-VoidLink, `execveat` is intentionally not called.

### 8.4 Anti-Analysis

- **Debugger detection**: Reads `/proc/self/status` for `TracerPid != 0`
- **EDR enumeration**: Scans `/proc/<pid>/comm` for known security product process names
- **Adaptive timing**: Switches to paranoid profile when EDR is detected, using higher jitter to evade cadence analysis

### 8.5 C2 Traffic Camouflage

See [Section 5](#5-camouflage-system). All C2 responses are encrypted (AES-256-GCM) and wrapped in legitimate-looking HTTP content types.

---

## 9. Detection Rules

### 9.1 YARA Rules (`detection/yara/`)

4 rule files containing 14 total rules targeting static artifacts:

| File | Rules | Targets |
|------|-------|---------|
| `voidlink_artifacts.yar` | 5 rules | Rootkit (LKM, eBPF), ICMP covert channel, filesystem artifacts, SRC request |
| `voidlink_implant.yar` | 3 rules | Zig binary detection, high-entropy ELF, cloud fingerprinting |
| `voidlink_loader.yar` | 3 rules | Stage 0 dropper (memfd_create+execveat), XOR config, Stage 1 downloader |
| `voidlink_simulation.yar` | 3 rules | Phantom-beacon confirmation, direct syscall patterns, C2 protocol strings |

### 9.2 Sigma Rules (`detection/sigma/`)

3 rule files containing 7 total rules for runtime behavioral correlation:

| File | Rules | Targets |
|------|-------|---------|
| `voidlink_syscall_sequence.yml` | fork→prctl→socket→connect→recvfrom→memfd_create chain, memfd_create with anonymous name |
| `voidlink_process_masquerade.yml` | prctl(PR_SET_NAME) to kworker names, parent-child PID masquerade patterns |
| `voidlink_ebpf_hooks.yml` | eBPF map creation, LKM loading, C2 network patterns |

### 9.3 Aegis Behavioral Profile (`detection/aegis/`)

`voidlink_cadence.json` defines:
- **IAT analysis parameters**: CV ranges for aggressive (0.15–0.25) and paranoid (0.25–0.40) profiles
- **Transport signatures**: Content-type mismatch detection, base64-in-comment patterns
- **User-Agent rotation detection**: Flag >3 distinct UAs from single source IP in 5 minutes
- **Session fingerprinting**: Detect handshake→heartbeat→sync endpoint chain
- **Known IOCs**: C2 IPs, ports, endpoints
- **MITRE mapping**: T1071.001, T1573.001, T1008, T1095, T1132.001

---

## 10. Payload Swap Points

> **⚡ CRITICAL SECTION** — These are the exact locations where benign payloads can be replaced with operational capabilities. Each swap point is marked with `// PAYLOAD SWAP:` comments in the source code.

### 10.1 C2 Server Swap Points (`handler.go`)

#### `/compile` — Serverside Rootkit Compilation

**File**: `c2/internal/handler/handler.go`, function `handleCompile`
**Current behavior**: Returns 256 bytes of zeroes with "DE-VOIDLINK-BENIGN-PLACEHOLDER" prefix.
**Swap**: Replace `placeholder` byte generation with actual compiled kernel module bytes (e.g., invoke gcc/make to compile a rootkit `.ko` from the `CompileRequest.KernelRelease`).

```go
// Current (benign):
placeholder := make([]byte, 256)
copy(placeholder, []byte("DE-VOIDLINK-BENIGN-PLACEHOLDER"))

// Operational swap: compile actual kernel module for target kernel version
// output := compileRootkit(req.KernelRelease, req.HiddenPorts)
```

#### `/stage1.bin` — Stage 1 Binary Download

**File**: `c2/internal/handler/handler.go`, function `handleStage1`
**Current behavior**: Returns 4096-byte benign ELF placeholder (valid header, zero body).
**Swap**: Replace `elfPlaceholder(4096)` with actual stage 1 binary bytes.

```go
// Current (benign):
w.Write(elfPlaceholder(4096))

// Operational swap: serve real stage 1 dropper
// w.Write(loadBinary("payloads/stage1.bin"))
```

#### `/implant.bin` — Implant Binary Download

**File**: `c2/internal/handler/handler.go`, function `handleImplant`
**Current behavior**: Returns 8192-byte benign ELF placeholder.
**Swap**: Replace `elfPlaceholder(8192)` with actual implant binary.

```go
// Current (benign):
w.Write(elfPlaceholder(8192))

// Operational swap: serve compiled Zig beacon (live build)
// w.Write(loadBinary("payloads/implant.bin"))
```

#### `elfPlaceholder` — ELF Binary Generator

**File**: `c2/internal/handler/handler.go`, function `elfPlaceholder`
**Current behavior**: Generates a valid-looking but non-functional ELF64 binary (valid magic + header, zero-filled body).
**Swap**: Replace entire function with file-loading logic for real binaries.

### 10.2 Zig Beacon Swap Points

#### Simulated Payload Write (`main.zig`)

**File**: `core/src/main.zig`, function `childSequence`, line ~187
**Current behavior**: Writes the string `"PHANTOM_LINK_SIMULATED_PAYLOAD"` to memfd.
**Swap**: Write actual received stage payload to memfd and call execveat.

```zig
// Current (benign):
const dummy_payload = "PHANTOM_LINK_SIMULATED_PAYLOAD";
const write_rc = syscall.sys_write_syscall(@intCast(memfd), dummy_payload.ptr, dummy_payload.len);

// Operational swap: write actual received payload
// const write_rc = syscall.sys_write_syscall(@intCast(memfd), recv_buf.ptr, @intCast(recv_rc));
```

#### execveat Skip (`main.zig`)

**File**: `core/src/main.zig`, line ~194-196
**Current behavior**: Logs execveat syscall number but never executes.
**Swap**: Actually call `execveat(memfd, "", argv, envp, AT_EMPTY_PATH)`.

```zig
// Current (benign):
config.jsonLogSyscall(config.SYS_execveat, "execveat", 0);
config.jsonLog("info", "execveat_skipped", "\"reason\":\"simulation safety -- never execute in simulator\"");

// Operational swap: uncomment and implement execveat
// const exec_rc = syscall.sys_execveat(memfd, "", null, null, config.AT_EMPTY_PATH);
```

### 10.3 VoidStream Key Swap

**Files**: 
- `c2/internal/protocol/voidstream.go:15` — `SharedSecret`
- `core/src/voidstream.zig:7` — `SHARED_SECRET`

**Current**: Hardcoded `"de-voidlink-test-key-do-not-use"`
**Swap**: Implement Diffie-Hellman key exchange or embed a per-deployment key.

### 10.4 Arsenal Plugin Swap Points

Each plugin's `plugin_exec()` function is a swap point. The current implementations are benign:

| Plugin | Current | Operational Swap |
|--------|---------|-----------------|
| `recon.c` | Read-only uname/getuid | Add network exfiltration, detailed enumeration |
| `cred_harvest.c` | Existence check only (`openat(O_PATH)`) | Read file contents, exfiltrate via C2 |
| `persist.c` | Writeability check only (`access(W_OK)`) | Create actual persistence entries |

---

## 11. Data Flow Diagrams

### 11.1 Handshake Flow

```
Beacon                               C2 Server
  │                                      │
  │  POST /api/v2/handshake              │
  │  Body: {hostname, os, kernel, ...}   │
  │─────────────────────────────────────►│
  │                                      │ 1. Parse registration
  │                                      │ 2. Set cadence profile (EDR-based)
  │                                      │ 3. Create session (UUIDv4)
  │                                      │ 4. JSON marshal response
  │                                      │ 5. AES-256-GCM encrypt
  │                                      │ 6. Camouflage wrap (rotating mode)
  │  HTTP 200                            │
  │  Content-Type: image/png (etc.)      │
  │  Body: [camouflaged encrypted data]  │
  │◄─────────────────────────────────────│
  │                                      │
  │ 1. Detect Content-Type               │
  │ 2. Unwrap camouflage                 │
  │ 3. AES-256-GCM decrypt              │
  │ 4. Parse JSON → session_id           │
  │                                      │
```

### 11.2 Beacon Loop Flow

```
Beacon                               C2 Server
  │                                      │
  │  [loop until max_iterations/runtime] │
  │                                      │
  │  GET /api/v2/heartbeat               │
  │  X-Session-ID: <uuid>                │
  │─────────────────────────────────────►│
  │                                      │ Touch(session_id)
  │  HTTP 200 {status: "ok", ts: ...}    │
  │◄─────────────────────────────────────│
  │                                      │
  │  sleep(computeInterval(profile))     │
  │  [jitter applied]                    │
  │                                      │
```

---

## 12. Security Architecture Decisions

### 12.1 Why Direct Syscalls?

VoidLink avoids libc entirely. Our simulation mirrors this because:
1. The syscall sequence IS the detection signal — eBPF tracepoints and audit logs see the same pattern
2. Defensive tools must detect direct syscalls, not just libc wrappers
3. Testing EDR hooking bypass is a stated goal

### 12.2 Why Real Crypto?

AES-256-GCM is not simulated — it's real encryption using Go's `crypto/aes` + `crypto/cipher` and Zig's `std.crypto.aead.aes_gcm`. This ensures:
1. Wire captures look identical to real VoidLink traffic
2. Network IDS/IPS must handle real encrypted C2 channels
3. Defenders can validate their decryption tooling against a known key

### 12.3 Why ELF Relocation?

The plugin loader performs real ELF relocation (not dlopen). This matches VoidLink's BOF approach and:
1. Tests EDR detection of in-memory code execution
2. Generates the same mmap→mprotect(RX) pattern
3. Exercises the same relocation types used by real implants

### 12.4 Why Benign by Default?

Every payload is intentionally benign:
- `/compile` returns placeholder bytes, not a compiled rootkit
- `/stage1.bin` and `/implant.bin` return valid ELF headers with zero bodies
- Plugins only read metadata or check existence — they never read credential contents or install persistence
- `execveat` is logged but never called
- `PHANTOM_LINK_SAFETY=1` is required for live mode

This allows the framework to be safely used in production security testing environments without risk of accidental damage.

---

*Last updated: February 2026*
*Maintained by: loudmumble*
