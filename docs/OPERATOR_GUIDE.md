# DE-VoidLink — Operator Guide

> How to build, deploy, configure, and extend the DE-VoidLink adversary simulation framework.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Building](#2-building)
3. [Running the C2 Server](#3-running-the-c2-server)
4. [Running the Beacon](#4-running-the-beacon)
5. [End-to-End Workflow](#5-end-to-end-workflow)
6. [Writing Custom Arsenal Plugins](#6-writing-custom-arsenal-plugins)
7. [Detection Rules](#7-detection-rules)
8. [Configuration Reference](#8-configuration-reference)
9. [Testing](#9-testing)
10. [Safety Features & Kill Switch](#10-safety-features--kill-switch)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Prerequisites

| Tool | Minimum Version | Purpose | Install |
|------|----------------|---------|---------|
| **Zig** | 0.15.2+ | Beacon (implant simulator) | [ziglang.org](https://ziglang.org/download/) (must be on PATH) |
| **Go** | 1.18+ | C2 server | Package manager or [go.dev](https://go.dev/dl/) |
| **GCC** | 11+ | Arsenal plugin compilation | Package manager |
| **YARA** | 4.1+ | Detection rule validation (optional) | Package manager |
| **curl** | Any | Testing C2 endpoints | Pre-installed on most Linux |
| **Python 3** | 3.8+ | E2E integration tests (optional) | Pre-installed on most Linux |

**Platform**: Linux x86_64 only (beacon uses direct Linux syscalls).

---

## 2. Building

### Build Everything

```bash
make
```

This builds all three components and places binaries in `build/`:

```
build/
├── phantom-beacon       # Zig beacon (statically linked ELF64)
├── c2server             # Go C2 server
└── arsenal/
    ├── recon.o           # Reconnaissance plugin
    ├── cred_harvest.o    # Credential path enumeration plugin
    └── persist.o         # Persistence vector enumeration plugin
```

### Build Individual Components

```bash
make core         # Zig beacon only
make core-debug   # Zig beacon with debug symbols
make c2           # Go C2 server only
make arsenal      # C plugin specimens only
```

### Clean Build

```bash
make clean        # Remove all build artifacts
```

### Zig Build Details

The beacon is built with `ReleaseSafe` optimization by default:

```bash
cd core && zig build -Doptimize=ReleaseSafe
```

For debug builds (with full debug info and safety checks):

```bash
cd core && zig build
```

### Arsenal Build Details

Plugins are compiled as ELF relocatable objects (NOT shared libraries):

```bash
gcc -c -fPIC -fno-stack-protector -nostdlib -ffreestanding -Wall -Wextra -O2 \
    -I include -o build/arsenal/recon.o recon.c
```

You can verify plugin correctness:

```bash
readelf -h build/arsenal/recon.o | grep Type    # Should show "REL (Relocatable file)"
nm build/arsenal/recon.o | grep plugin          # Should show plugin_info, plugin_init, plugin_exec, plugin_cleanup
```

---

## 3. Running the C2 Server

### Basic Usage

```bash
./build/c2server --bind 127.0.0.1:8080 --mode voidlink --verbose
```

### All CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--bind` | `127.0.0.1:8080` | Listen address. Non-localhost triggers a warning. |
| `--mode` | `voidlink` | Traffic mode: `voidlink` (adaptive beaconing) or `ai-cadence` (LLM token timing) |
| `--max-runtime` | `300` | Auto-shutdown after N seconds. Set to `0` to disable. |
| `--verbose` | `false` | Enable verbose logging (request details, encryption debug) |
| `--tls` | `false` | Enable TLS (not yet implemented — flag accepted but server uses plain HTTP) |

### C2 Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v2/handshake` | Client registration. Send JSON body with system info. Returns encrypted session config. |
| `POST` | `/api/v2/sync` | Task synchronization. Send session_id + task results. |
| `GET` | `/api/v2/heartbeat` | Keep-alive. Set `X-Session-ID` header. |
| `POST` | `/compile` | SRC simulation. Send kernel_release, hidden_ports, has_gcc. Returns placeholder bytes. |
| `GET` | `/stage1.bin` | Download stage 1 binary placeholder (4096 bytes, valid ELF header). |
| `GET` | `/implant.bin` | Download implant binary placeholder (8192 bytes, valid ELF header). |
| `POST` | `/api/v2/kill` | **Kill switch**. Initiates graceful server shutdown. |

### Testing C2 Manually with curl

```bash
# Handshake (register a session)
curl -s -X POST http://127.0.0.1:8080/api/v2/handshake \
  -H "Content-Type: application/json" \
  -d '{"hostname":"test-host","os":"linux","kernel":"6.1.0","arch":"x86_64","uid":1000,"cloud_provider":"","container":false,"edr_detected":[]}' \
  -o /tmp/handshake_response

# Note: response is VoidStream-encrypted + camouflaged (not plaintext JSON)

# Heartbeat (requires session_id from server log)
curl -s http://127.0.0.1:8080/api/v2/heartbeat \
  -H "X-Session-ID: <session-id-from-log>"

# Compile endpoint
curl -s -X POST http://127.0.0.1:8080/compile \
  -H "Content-Type: application/json" \
  -d '{"kernel_release":"6.1.0","hidden_ports":[4444],"has_gcc":true}' \
  -o /tmp/compile_output

# Download stage 1
curl -s http://127.0.0.1:8080/stage1.bin -o /tmp/stage1.bin
xxd -l 16 /tmp/stage1.bin   # Should show ELF magic: 7f454c46

# Kill switch
curl -s -X POST http://127.0.0.1:8080/api/v2/kill
```

### C2 Server Output

The server writes structured JSON logs to stdout:

```json
{"ts":"2026-02-26T10:30:00Z","event":"handshake","session_id":"a1b2c3d4-...","remote_addr":"127.0.0.1:54321","profile":"aggressive"}
{"ts":"2026-02-26T10:30:04Z","event":"heartbeat","session_id":"a1b2c3d4-...","interval_ms":4096}
```

---

## 4. Running the Beacon

### Dry-Run Mode (Default, Safe)

```bash
./build/phantom-beacon --dry-run --c2-addr 127.0.0.1 --c2-port 8080
```

Logs all syscalls and C2 operations to stderr as JSON without executing any live syscalls.

### Live Mode (Executes Real Syscalls)

```bash
PHANTOM_LINK_SAFETY=1 ./build/phantom-beacon --live \
  --c2-addr 127.0.0.1 \
  --c2-port 8080 \
  --max-runtime 30 \
  --max-iterations 5 \
  --verbose
```

**Requirements for live mode**:
- `PHANTOM_LINK_SAFETY=1` environment variable MUST be set
- Without it, the beacon forces dry-run mode regardless of `--live`

### All Beacon CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--c2-addr` | `127.0.0.1` | C2 server IP address |
| `--c2-port` | `8080` | C2 server port |
| `--dry-run` | (default) | Log operations without executing. Safe mode. |
| `--live` | off | Execute real syscalls (fork, socket, connect, memfd_create). Requires `PHANTOM_LINK_SAFETY=1`. |
| `--max-runtime` | `60` | Auto-terminate after N seconds |
| `--max-iterations` | `10` | Maximum beacon loop iterations |
| `--verbose` | `false` | Detailed logging (sleep intervals, VoidStream debug) |
| `--no-masquerade` | `false` | Skip process name masquerade |
| `--no-evasion` | `false` | Skip EDR scanning and debugger detection |
| `--no-plugins` | `false` | Skip arsenal plugin loading |
| `--arsenal-dir` | `./build/arsenal` | Directory containing arsenal plugin .o files |

### Beacon Output

The beacon writes structured JSON to stderr:

```json
{"ts":1740567000,"level":"info","msg":"SAFETY: de-voidlink beacon -- adversary simulation only","mode":"live","c2":"127.0.0.1:8080","max_runtime":30}
{"ts":1740567000,"level":"info","msg":"masquerade","name":"[kworker/0:0]","result":0}
{"ts":1740567000,"level":"info","msg":"evasion_scan","products_found":0,"risk_score":0,"profile":"aggressive"}
{"ts":1740567001,"level":"info","msg":"syscall","nr":57,"name":"fork","result":12345}
{"ts":1740567001,"level":"info","msg":"handshake","session_id":"a1b2c3d4-...","status":"ok"}
{"ts":1740567005,"level":"info","msg":"heartbeat","session_id":"a1b2c3d4-..."}
```

---

## 5. End-to-End Workflow

### Basic Simulation

```bash
# Terminal 1: Start C2 server
./build/c2server --bind 127.0.0.1:8080 --mode voidlink --verbose

# Terminal 2: Run beacon in dry-run (safe)
./build/phantom-beacon --dry-run --c2-addr 127.0.0.1 --c2-port 8080

# Terminal 2: Run beacon in live mode
PHANTOM_LINK_SAFETY=1 ./build/phantom-beacon --live \
  --c2-addr 127.0.0.1 --c2-port 8080 \
  --max-runtime 30 --max-iterations 5
```

### With Detection Tool Monitoring

For testing defensive tools, run the beacon while monitoring with:

```bash
# eBPF syscall tracing (Sentinel)
sudo sentinel --config sentinel.yaml &

# YARA scanning
yara -r detection/yara/*.yar build/phantom-beacon

# Network capture for Aegis analysis
sudo tcpdump -i lo port 8080 -w /tmp/voidlink.pcap &

# Then run the live beacon
PHANTOM_LINK_SAFETY=1 ./build/phantom-beacon --live --c2-addr 127.0.0.1 --c2-port 8080
```

### AI-Cadence Mode

To test detection of AI-traffic-mimicking beaconing:

```bash
./build/c2server --bind 127.0.0.1:8080 --mode ai-cadence --verbose
```

---

## 6. Writing Custom Arsenal Plugins

### Plugin Template

Create a new file in `arsenal/`:

```c
// arsenal/my_plugin.c
#include "plugin_api.h"

static PluginInfo info = {
    .name = "my_plugin",
    .version = "1.0.0",
    .description = "Description of what this plugin does",
    .author = "de-voidlink",
    .api_version = PLUGIN_API_VERSION,
    .capabilities = PLUGIN_CAP_FILESYSTEM,  // Set appropriate capabilities
};

PluginInfo* plugin_info(void) {
    return &info;
}

int plugin_init(PluginContext *ctx) {
    (void)ctx;
    return PLUGIN_OK;
}

int plugin_exec(PluginContext *ctx) {
    // Always check dry-run mode first
    if (ctx->mode == EXEC_MODE_DRY_RUN) {
        OUTPUT_STRING(ctx, "{\"plugin\":\"my_plugin\",\"mode\":\"dry_run\"}\n");
        return PLUGIN_DRY_RUN;
    }

    // Use ctx->syscalls for direct syscall access
    if (ctx->syscalls) {
        long result = ctx->syscalls->syscall0(39);  // getpid
        // ... process result ...
    }

    // Write output as JSON to ctx->output
    OUTPUT_STRING(ctx, "{\"plugin\":\"my_plugin\",\"status\":\"ok\"}\n");

    return PLUGIN_OK;
}

int plugin_cleanup(PluginContext *ctx) {
    (void)ctx;
    return PLUGIN_OK;
}
```

### Compilation

Add your plugin to `arsenal/Makefile`:

```makefile
PLUGINS := recon cred_harvest persist my_plugin
```

Or compile manually:

```bash
gcc -c -fPIC -fno-stack-protector -nostdlib -ffreestanding \
    -Wall -Wextra -O2 -I arsenal/include \
    -o build/arsenal/my_plugin.o arsenal/my_plugin.c
```

### Registration with Beacon

Add the plugin filename to `core/src/plugin_loader.zig`:

```zig
const PLUGIN_FILES = [_][]const u8{
    "recon.o",
    "cred_harvest.o",
    "persist.o",
    "my_plugin.o",        // Add here
};
```

### Plugin API Reference

#### Capability Flags

```c
PLUGIN_CAP_NETWORK     (1 << 0)  // Plugin needs network access
PLUGIN_CAP_FILESYSTEM  (1 << 1)  // Plugin needs filesystem access
PLUGIN_CAP_PROCESS     (1 << 2)  // Plugin needs process operations
PLUGIN_CAP_PRIVILEGED  (1 << 3)  // Plugin needs root/CAP_*
PLUGIN_CAP_STEALTH     (1 << 4)  // Plugin uses evasion techniques
```

#### Return Codes

```c
PLUGIN_OK       (0)   // Success
PLUGIN_ERR      (-1)  // Error
PLUGIN_SKIP     (-2)  // Plugin chose not to execute
PLUGIN_DRY_RUN  (-3)  // Dry run completed (no side effects)
```

#### Output Macros

```c
OUTPUT_WRITE(ctx, buf, len)   // Write raw bytes to output buffer
OUTPUT_STRING(ctx, str)       // Write null-terminated string
```

#### SyscallTable Usage

The `SyscallTable` provides direct syscall access without libc:

```c
// Example: getpid
long pid = ctx->syscalls->syscall0(39);

// Example: openat(AT_FDCWD, "/etc/hostname", O_RDONLY, 0)
long fd = ctx->syscalls->syscall4(257, -100, (long)"/etc/hostname", 0, 0);
if (fd >= 0) {
    char buf[256];
    long n = ctx->syscalls->syscall3(0, fd, (long)buf, 256);  // read
    ctx->syscalls->syscall1(3, fd);  // close
}
```

### Important Constraints

- **No libc**: Plugins are compiled with `-nostdlib -ffreestanding`. You cannot use `printf`, `malloc`, `strlen`, etc. Use the `OUTPUT_*` macros and SyscallTable.
- **No dynamic linking**: Plugins are ET_REL objects, not shared libraries. No PLT/GOT resolution beyond `memcpy`.
- **Stack-allocated only**: No heap. Use stack buffers for all data.
- **Max output**: 64KB (`PLUGIN_MAX_OUTPUT`). The `OutputBuffer` will stop accepting data at capacity.

---

## 7. Detection Rules

### Modifying YARA Rules

YARA rules are in `detection/yara/*.yar`. To add a new rule:

1. Create or edit a `.yar` file
2. Validate: `yara --fail-on-warnings -w detection/yara/your_rule.yar /dev/null`
3. Test against the beacon: `yara detection/yara/your_rule.yar build/phantom-beacon`

### Modifying Sigma Rules

Sigma rules are in `detection/sigma/*.yml`. These define behavioral correlations for SIEM/XDR platforms:

1. Edit the `.yml` file following [Sigma specification](https://sigmahq.io/)
2. Validate with `sigma-cli` or your SIEM's Sigma converter
3. Rules target syscall telemetry (from eBPF/auditd) and process metadata

### Modifying Aegis Profile

The Aegis behavioral profile is `detection/aegis/voidlink_cadence.json`. Key fields to tune:

```json
{
  "profiles": {
    "aggressive": {
      "base_interval_ms": 4096,        // Must match config.zig PROFILE_AGGRESSIVE
      "jitter_percent": 20,
      "regularity_threshold": 0.85     // Detection sensitivity
    }
  },
  "detection_strategies": {
    "iat_analysis": {
      "aggressive_cv_range": [0.15, 0.25]  // Coefficient of variation thresholds
    }
  }
}
```

### Validating All Rules

```bash
make detection         # Validate YARA and list Sigma rules
make detection-yara    # YARA only
make detection-sigma   # Sigma only (lists files)
```

---

## 8. Configuration Reference

### Config Constants (`core/src/config.zig`)

| Constant | Value | Description |
|----------|-------|-------------|
| `PRCTL_MAGIC` | `0x564C` | "VL" magic for prctl operations |
| `ICMP_MAGIC` | `0xC0DE` | Magic for ICMP channel |
| `XOR_KEY` | `0xAA` | XOR encoding key |
| `DEFAULT_C2_ADDR` | `127.0.0.1` | Default C2 address |
| `DEFAULT_C2_PORT` | `8080` | Default C2 port |
| `SAFETY_ENV_VAR` | `PHANTOM_LINK_SAFETY` | Env var name for safety check |

### Timing Profiles

| Profile | Base Interval | Jitter | Use When |
|---------|---------------|--------|----------|
| Aggressive | 4096 ms | ±20% | No EDR detected — slower beaconing, lower risk posture |
| Paranoid | 1024 ms | ±30% | EDR detected — faster beaconing to exfiltrate before containment (matches real VoidLink behavior) |

### VoidStream Protocol Constants

| Constant | Value | Description |
|----------|-------|-------------|
| Nonce size | 12 bytes | AES-GCM nonce |
| Tag size | 16 bytes | GCM authentication tag |
| Length prefix | 4 bytes | Big-endian uint32 |
| Shared secret | `de-voidlink-test-key-do-not-use` | SHA-256'd to derive AES-256 key |

---

## 9. Testing

### Run All Tests

```bash
make test    # Builds everything, then runs test/run_tests.sh
```

### Test Phases

The integration test suite (`test/run_tests.sh`) runs 4 phases:

| Phase | Tests | Description |
|-------|-------|-------------|
| **1: C2 Endpoints** | 14 tests | Handshake (registration + body + session ID), heartbeat (valid + JSON + invalid), sync, compile, stage1, implant, method guard, EDR profile, kill switch + exit |
| **2: Detection Rules** | 3 tests | YARA validation, Sigma file presence, Aegis JSON validity |
| **3: Arsenal Plugins** | 6 tests | ET_REL type check, plugin API symbol presence for each .o file |
| **4: Beacon Integration** | 3 tests | Beacon→C2 handshake, heartbeat loop, VoidLink syscall sequence |

### E2E Integration Tests

The Python E2E test (`test/e2e_integration.py`) validates against the full detection stack:

```bash
PHANTOM_LINK_SAFETY=1 python3 test/e2e_integration.py
```

This requires Malscope, Sentinel, and Aegis to be installed. Tests 4 phases:
1. **Malscope** static analysis (YARA + ELF indicators)
2. **Sentinel** syscall detection (memfd_create, masquerade, fork→memfd correlation)
3. **Aegis** C2 beaconing detection (cadence classification, C2 profile match)
4. **YARA** direct binary scan

### Unit Tests

```bash
make test-core    # Run Zig unit tests for beacon components
```

---

## 10. Safety Features & Kill Switch

### Safety Controls Summary

| Control | Mechanism | Effect |
|---------|-----------|--------|
| **PHANTOM_LINK_SAFETY** | Environment variable | Must be set to `"1"` for live mode. Without it, beacon forces dry-run. |
| **--dry-run** | CLI flag (default) | All operations logged but not executed. No real syscalls, no network. |
| **--max-runtime** | CLI flag | Auto-terminates after N seconds. Beacon: 60s default. C2: 300s default. |
| **--max-iterations** | CLI flag | Beacon loop exits after N heartbeats. Default: 10. |
| **Kill switch** | `POST /api/v2/kill` | Immediately shuts down C2 server. No authentication required. |
| **Localhost binding** | C2 default | Binds to `127.0.0.1`. Non-localhost prints a warning. |
| **No execveat** | Code design | `execveat` is logged but never executed. Payload write uses dummy string. |
| **Benign payloads** | Code design | `/stage1.bin`, `/implant.bin` return valid-looking but non-functional ELF binaries. `/compile` returns placeholder bytes. |
| **Benign plugins** | Code design | Plugins only read metadata or check file existence — never read credentials or install persistence. |

### Using the Kill Switch

```bash
# From any terminal:
curl -X POST http://127.0.0.1:8080/api/v2/kill

# Server responds with {"status":"shutting_down"} and exits
```

### Emergency Shutdown

If the C2 server doesn't respond to the kill switch:

```bash
# Find and kill the processes
pkill c2server
pkill phantom-beacon

# Or use the PID:
kill $(pgrep c2server)
```

---

## 11. Troubleshooting

### Beacon can't connect to C2

```
{"level":"warn","msg":"handshake","error":"connect_failed","rc":-111}
```

**Fix**: Ensure C2 server is running and accessible:
```bash
curl -s http://127.0.0.1:8080/api/v2/heartbeat
```

### Safety check forces dry-run

```
{"level":"warn","msg":"PHANTOM_LINK_SAFETY!=1, forcing dry-run"}
```

**Fix**: Set the environment variable:
```bash
export PHANTOM_LINK_SAFETY=1
# or prefix the command:
PHANTOM_LINK_SAFETY=1 ./build/phantom-beacon --live ...
```

### Plugin loading fails

```
{"level":"debug","msg":"plugin_loader","error":"file_not_found"}
```

**Fix**: Ensure arsenal plugins are built and in the expected directory:
```bash
make arsenal
ls -la build/arsenal/*.o
```

### VoidStream decryption fails

```
{"level":"debug","msg":"voidstream_fallback","reason":"decrypt_failed_trying_plain"}
```

This happens when the beacon can't decrypt the C2 response. Possible causes:
- Shared secret mismatch between beacon and C2 (should not happen unless you modified one)
- Response body truncated (network issue)
- C2 server version mismatch

The beacon falls back to plain JSON parsing automatically.

### Build errors

**Zig not found**: Ensure Zig 0.15.2+ is installed and available on your PATH.

**Go module errors**: Run `go mod tidy` in the `c2/` directory.

**GCC missing**: Install gcc via your package manager.

---

*Last updated: February 2026*
*Maintained by: loudmumble*
