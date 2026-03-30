# payloads/

Pre-built beacon binaries served by the C2 in `OPERATIONAL=1` mode.

**These files are NOT committed to git** — they are generated artifacts.

## How to populate

```bash
# Build everything (operational mode populates stage1.bin and implant.bin)
make OPERATIONAL=1

# Or populate payloads only (requires beacon already built):
make payloads
```

## Contents

| File | Purpose |
|------|---------|
| `stage1.bin` | First-stage stager binary (copy of phantom-beacon) |
| `implant.bin` | Full implant binary (copy of phantom-beacon) |

Both files are the same compiled `phantom-beacon` binary.
The C2 `payload_operational.go` reads these when `/stage1.bin` or `/implant.bin`
is requested by the beacon, and also as fallback for the `/compile` endpoint.

## Safety

- In benign builds (`OPERATIONAL=0`), the C2 never serves real binaries.
- In operational builds, these binaries are the de-voidlink simulation tool, not
  functional malware. They replicate VoidLink signatures for detection testing only.
- `PHANTOM_LINK_SAFETY=1` must be set for the beacon to run in live mode.
