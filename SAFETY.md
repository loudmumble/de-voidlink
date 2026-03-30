# de-voidlink Safety Controls

## What This Is

de-voidlink is an **adversary simulation framework** for testing defensive security tools
(Malscope, Aegis, Sentinel). It generates detectable artifacts and behaviors that mimic
the VoidLink malware framework, allowing defenders to validate their detection capabilities.

This is analogous to Atomic Red Team, MITRE Caldera, or Cobalt Strike's adversary simulation mode.

## What This Is NOT

This is NOT functional malware. It does NOT:
- Exfiltrate data to external servers
- Establish persistent access to compromised systems
- Destroy, encrypt, or modify production data
- Spread laterally across networks
- Communicate with any external C2 infrastructure

## Safety Controls

### Network Isolation
- The mock C2 server binds to `127.0.0.1` by default
- The `--bind` flag can override this for lab environments ONLY
- No external network connections are made by any component
- All C2 communication is between local beacon and local mock server

### Kill Switch
- `POST /api/v2/kill` immediately terminates the C2 server
- `SIGINT` / `SIGTERM` gracefully shuts down all components
- `--max-runtime` auto-terminates after N seconds (beacon default: 60s, C2 default: 300s)
- The `--dry-run` flag logs all actions without executing syscalls

### Payload Safety
- All plugin payloads are benign (hello-world, system info collection)
- The plugin API supports payload swapping for research purposes
- In the default benign build, `execveat` is logged but never executed
- Operational builds (`OPERATIONAL=1`) execute `execveat` on C2-received payloads
- memfd_create payloads contain benign placeholders in benign mode

### Runtime Guards
- `PHANTOM_LINK_SAFETY=1` environment variable must be set for live mode
- Without it, the beacon forces dry-run mode and logs a safety warning
- All components log to stdout/stderr with structured JSON for audit

## Deployment Rules

1. Run ONLY in isolated lab environments (VMs, dedicated test hosts)
2. Never run on production systems
3. Never run on systems with real user data
4. Ensure no network egress from the test environment
5. Review all plugin payloads before loading
6. Keep `PHANTOM_LINK_SAFETY=1` set at all times outside automated test suites

## Legal

This tool is for authorized security testing and research only. Users are responsible
for ensuring compliance with applicable laws and organizational policies. The authors
assume no liability for misuse.
