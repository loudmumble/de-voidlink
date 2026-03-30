# de-voidlink

VoidLink adversary simulation framework for testing defensive security tools.

Replicates the exact techniques, syscall sequences, and C2 protocol of the [VoidLink](https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/) malware framework using the same Zig + C + Go tech stack. Generates realistic detection artifacts for evaluating YARA rules, Sigma correlations, eBPF monitors, and behavioral IDS systems.

**This is a security research tool. It does not contain functional malware payloads.**

## Architecture

```
de-voidlink/
  core/       Zig implant simulator — direct syscalls, VoidStream protocol, process masquerade
  c2/         Go mock C2 server — VoidStream encryption, HTTP camouflage, adaptive beaconing
  arsenal/    C plugin specimens — ET_REL relocatable objects (BOF-style)
  detection/  YARA, Sigma, and Aegis detection rules
  test/       Integration test suite
```

| Component | Language | Binary | Description |
|-----------|----------|--------|-------------|
| phantom-beacon | Zig | `build/phantom-beacon` | Statically linked ELF64. Executes VoidLink's syscall fingerprint, beacons to C2 with VoidStream-encrypted handshake, adaptive timing with jitter. |
| c2server | Go | `build/c2server` | HTTP server implementing all VoidLink C2 endpoints. AES-256-GCM encryption, 5 HTTP camouflage modes (PNG/JS/CSS/HTML/JSON), session management. |
| arsenal/*.o | C | `build/arsenal/*.o` | Relocatable ELF objects with `plugin_exec`/`plugin_init`/`plugin_info`/`plugin_cleanup` symbols. Recon, credential path enumeration, persistence simulation. |

## Quick Start

```bash
# Build everything
make

# Run C2 server (localhost only, auto-kills after 300s)
./build/c2server --bind 127.0.0.1:8080 --mode voidlink --verbose

# In another terminal — run beacon in dry-run mode (no live syscalls)
./build/phantom-beacon --dry-run --c2-addr 127.0.0.1 --c2-port 8080

# Run beacon in live mode (executes real fork/socket/connect/memfd_create sequence)
PHANTOM_LINK_SAFETY=1 ./build/phantom-beacon --live --c2-addr 127.0.0.1 --c2-port 8080 --max-runtime 30

# Run integration tests
make test
```

## Safety Controls

| Control | Description |
|---------|-------------|
| `PHANTOM_LINK_SAFETY=1` | Required env var for live mode. Without it, beacon forces dry-run. |
| `--dry-run` | Logs all syscalls and C2 operations without executing them. Default mode. |
| `--max-runtime N` | Auto-terminates after N seconds. Beacon default: 60s, C2 default: 300s. |
| `POST /api/v2/kill` | C2 kill switch endpoint for immediate shutdown. |
| Localhost binding | C2 defaults to `127.0.0.1:8080`. Non-localhost triggers a warning. |
| No execveat (benign) | In the default benign build, `execveat` is logged but never executed. Operational builds (`OPERATIONAL=1`) execute `execveat` on received payloads. |
| Benign payloads | Stage downloads return valid ELF headers with zero-filled bodies. `/compile` returns placeholder bytes. |

## VoidLink Syscall Fingerprint

The beacon replicates VoidLink's exact detection signature (from [Sysdig TRT analysis](https://www.sysdig.com/blog/voidlink-threat-analysis-sysdig-discovers-c2-compiled-kernel-rootkits)):

```
fork(57) → prctl(157) → socket(41) → connect(42) → recvfrom(45) → memfd_create(319) → write(1) → [execveat(322) logged only]
```

In live mode, the beacon forks a child process that executes this sequence using direct Linux syscalls (no libc). The parent continues to the beacon loop. This triggers the same eBPF tracepoint and audit log patterns as the real malware.

## VoidStream Protocol

C2 responses are encrypted and camouflaged to match VoidLink's wire format:

1. **Encryption**: AES-256-GCM with key derived via SHA-256 of a shared secret
2. **Wire format**: `[4-byte BE length][12-byte nonce][ciphertext][16-byte GCM tag]`
3. **Camouflage**: Encrypted payload wrapped in legitimate HTTP responses, rotating through:
   - `image/png` — Valid PNG with payload in IDAT chunk
   - `application/javascript` — `var _0x=["<base64>"];`
   - `text/css` — `/* font-data: <base64> */`
   - `text/html` — `<!-- <base64> -->`
   - `application/json` — `{"data":"<base64>","status":"ok"}`

The beacon implements full VoidStream decryption and camouflage unwrapping to complete real handshake/heartbeat cycles.

## C2 Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v2/handshake` | Client registration. Returns encrypted session config. |
| POST | `/api/v2/sync` | Task synchronization. |
| GET | `/api/v2/heartbeat` | Keep-alive. Requires `X-Session-ID` header. |
| POST | `/compile` | Serverside Rootkit Compilation simulation. Returns benign bytes. |
| GET | `/stage1.bin` | Stage 1 download. Returns benign ELF placeholder (4096 bytes). |
| GET | `/implant.bin` | Implant download. Returns benign ELF placeholder (8192 bytes). |
| POST | `/api/v2/kill` | Safety kill switch. Graceful server shutdown. |

## Adaptive Beaconing

Two traffic modes for testing behavioral detection:

**`--mode=voidlink`** (default): Risk-based timing matching real VoidLink profiles.

| Profile | Trigger | Base Interval | Jitter |
|---------|---------|---------------|--------|
| aggressive | No EDR detected | 4096ms | ±20% |
| paranoid | EDR detected | 1024ms (base), up to 5000ms | ±30% |

**`--mode=ai-cadence`**: Mimics LLM autoregressive token generation timing for testing AI-traffic detection. Alternates between burst phases (50–150ms) and thinking pauses (500–2000ms).

## Detection Rules

### YARA (14 rules, 4 files)
Target static artifacts in VoidLink binaries — magic bytes, XOR keys, embedded paths, ELF characteristics.

```bash
make detection-yara  # Validate all rules
```

### Sigma (7 rules, 3 files)
Correlate runtime behavior — syscall sequences, process name masquerade, eBPF map creation, LKM loading, C2 network patterns.

### Aegis Behavioral Profile
JSON cadence configuration for inter-arrival time analysis, IAT histogram parameters, and transport signature detection.

## Build Requirements

| Tool | Version | Purpose |
|------|---------|---------|
| Zig | 0.15.2+ | Beacon (implant simulator) |
| Go | 1.18+ | C2 server |
| GCC | 11+ | Arsenal plugins |
| YARA | 4.1+ | Detection rule validation (optional) |

```bash
make            # Build all
make core       # Zig beacon only
make c2         # Go C2 server only
make arsenal    # C plugins only
make test       # Run integration tests
make clean      # Remove build artifacts
make info       # Show component overview
```

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/INTERNAL.md`](docs/INTERNAL.md) | Internal developer guide — architecture, VoidStream crypto, camouflage system, plugin loader, payload swap points |
| [`docs/OPERATOR_GUIDE.md`](docs/OPERATOR_GUIDE.md) | Operator guide — building, configuring, running, writing custom plugins, detection rules |
| [`SAFETY.md`](SAFETY.md) | Safety controls and responsible use policy |

## References

- [Check Point Research — VoidLink Part 1](https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/) — Architecture, plugin API, rootkit variants, C2 protocol
- [Check Point Research — VoidLink Part 2](https://research.checkpoint.com/2026/voidlink-early-ai-generated-malware-framework/) — AI-generated development, TRAE SOLO IDE, 6-day timeline
- [Sysdig TRT — VoidLink Threat Analysis](https://www.sysdig.com/blog/voidlink-threat-analysis-sysdig-discovers-c2-compiled-kernel-rootkits) — Syscall sequences, magic values, timing profiles, IOCs
- [Ontinue — Dissecting an AI-Generated C2 Implant](https://www.ontinue.com/resource/voidlink-dissecting-an-ai-generated-c2-implant/) — Binary analysis, module registry, AI pattern indicators

## Related Projects

- **[Aegis](https://github.com/loudmumble/aegis)** — Behavioral IDS validated against DE-VoidLink's beaconing patterns
- **[syscalld](https://github.com/loudmumble/syscalld)** — Kernel sensor framework providing syscall telemetry

## License

MIT — see [LICENSE](LICENSE).

---

Built by [loudmumble](https://github.com/loudmumble). Research and tooling at [loudmumble.com](https://loudmumble.com).
