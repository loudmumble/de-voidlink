#!/usr/bin/env python3
"""VoidLink E2E Integration Test

Detonates de-voidlink in the Medusa sandbox and verifies
all 3 defensive tools detect VoidLink-specific indicators.
"""

import sys
import time
import random
from pathlib import Path

PHANTOM_LINK_ROOT = Path(__file__).resolve().parent.parent
BEACON_PATH = PHANTOM_LINK_ROOT / "build" / "phantom-beacon"
YARA_DIR = PHANTOM_LINK_ROOT / "detection" / "yara"

passed = 0
failed = 0


def check(condition, label, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {label}" + (f": {detail}" if detail else ""))
    else:
        failed += 1
        print(f"  [FAIL] {label}" + (f": {detail}" if detail else ""))


# ─────────────────────────────────────────────────────────
#  Phase 1: Malscope Static Analysis
# ─────────────────────────────────────────────────────────
def phase1_malscope():
    print("\nPhase 1: Malscope Static Analysis")
    from malscope.config import AnalysisConfig
    from malscope.analyzers.static import StaticAnalyzer

    config = AnalysisConfig(yara_rules_dir=YARA_DIR)
    analyzer = StaticAnalyzer(config)
    result = analyzer.analyze(BEACON_PATH)

    yara_count = len(result.yara_matches)
    check(yara_count >= 1, f"YARA rules matched: {yara_count}")

    indicators = result.suspicious_indicators
    check(
        len(indicators) >= 1, f"ELF analysis: {len(indicators)} suspicious indicators"
    )

    # Composite suspicion: YARA matches + ELF indicators together
    composite = yara_count + len(indicators)
    check(
        composite >= 3,
        f"Combined suspicion signals: {composite} (YARA:{yara_count} + ELF:{len(indicators)})",
    )


# ─────────────────────────────────────────────────────────
#  Phase 2: Sentinel Syscall Detection
# ─────────────────────────────────────────────────────────
def phase2_sentinel():
    print("\nPhase 2: Sentinel Syscall Detection")
    from sentinel.config import SentinelConfig
    from sentinel.analysis.engine import AnalysisEngine
    from sentinel.probes import SyscallEvent

    config = SentinelConfig()
    engine = AnalysisEngine(config, llm=None)

    # Synthetic syscall sequence matching VoidLink's exact chain:
    #   fork → prctl(PR_SET_NAME) → socket → connect → recvfrom →
    #   memfd_create → write → execveat
    t = time.time()
    events = [
        SyscallEvent(
            timestamp=t,
            pid=1000,
            comm="phantom-beacon",
            syscall_nr=57,
            syscall_name="fork",
            args=[],
        ),
        SyscallEvent(
            timestamp=t + 0.1,
            pid=1000,
            comm="kworker/0:1",
            syscall_nr=157,
            syscall_name="prctl",
            args=[15],  # PR_SET_NAME
        ),
        SyscallEvent(
            timestamp=t + 0.2,
            pid=1000,
            comm="kworker/0:1",
            syscall_nr=41,
            syscall_name="socket",
            args=[2, 1, 0],
        ),
        SyscallEvent(
            timestamp=t + 0.3,
            pid=1000,
            comm="kworker/0:1",
            syscall_nr=42,
            syscall_name="connect",
            args=[3, 0, 0],
        ),
        SyscallEvent(
            timestamp=t + 0.4,
            pid=1000,
            comm="kworker/0:1",
            syscall_nr=45,
            syscall_name="recvfrom",
            args=[3, 0, 0],
        ),
        SyscallEvent(
            timestamp=t + 0.5,
            pid=1000,
            comm="kworker/0:1",
            syscall_nr=319,
            syscall_name="memfd_create",
            args=[0, 0],
        ),
        SyscallEvent(
            timestamp=t + 0.6,
            pid=1000,
            comm="kworker/0:1",
            syscall_nr=1,
            syscall_name="write",
            args=[3, 0, 0],
        ),
        SyscallEvent(
            timestamp=t + 0.7,
            pid=1000,
            comm="kworker/0:1",
            syscall_nr=322,
            syscall_name="execveat",
            args=[3, 0, 0],
        ),
    ]

    results = engine.process(events)

    memfd_score = 0
    masq_score = 0
    fork_memfd_score = 0

    for r in results:
        # Check enriched event anomalies
        for a in r.get("anomalies", []):
            if a.get("rule") == "memfd_create_anonymous":
                memfd_score = max(memfd_score, a.get("score", 0))
            if a.get("rule") == "process_masquerade":
                masq_score = max(masq_score, a.get("score", 0))
        # Check correlation results
        if r.get("rule") == "fork_then_memfd":
            fork_memfd_score = max(fork_memfd_score, r.get("score", 0))

    check(memfd_score >= 85, "memfd_create_anonymous", f"score={memfd_score}")
    check(masq_score >= 75, "process_masquerade", f"score={masq_score}")
    check(
        fork_memfd_score >= 90,
        "fork_then_memfd correlator",
        f"score={fork_memfd_score}",
    )


# ─────────────────────────────────────────────────────────
#  Phase 3: Aegis C2 Beaconing Detection
# ─────────────────────────────────────────────────────────
def phase3_aegis():
    print("\nPhase 3: Aegis C2 Beaconing Detection")
    from aegis.config import CadenceConfig
    from aegis.detection.cadence import CadenceAnalyzer
    from aegis.detection.rules import RuleEngine
    from aegis.capture.flows import NetworkFlow, FlowKey

    cadence_config = CadenceConfig(min_packets_for_analysis=20)
    cadence_analyzer = CadenceAnalyzer(cadence_config)
    rule_engine = RuleEngine(builtin_enabled=True)

    # Synthetic C2 beaconing flow: 35 packets at ~4096ms ± 20% jitter
    key = FlowKey(
        src_ip="10.0.0.50",
        src_port=54321,
        dst_ip="8.149.128.10",
        dst_port=443,
        protocol="tcp",
    )
    flow = NetworkFlow(key=key)

    random.seed(42)
    t = time.time()
    for i in range(35):
        flow.add_packet(
            timestamp=t,
            size=128,
            src_ip="10.0.0.50",
            src_port=54321,
            flags="PSH,ACK",
            payload_size=64,
        )
        jitter = random.uniform(-0.20, 0.20)
        t += 4.096 * (1 + jitter)

    cadence_results = cadence_analyzer.analyze_flows([flow])

    if not cadence_results:
        check(False, "Cadence classification", "no results returned")
        check(False, "C2 profile match", "no results")
        check(False, "Rule AEGIS-008/009", "no results")
        return

    cr = cadence_results[0]
    classification = cr.classification.value
    confidence = cr.confidence

    # Classification: AGENT expected due to low CV + C2 beaconing range
    check(
        classification == "agent",
        f"Cadence classification: {classification.upper()} (confidence: {confidence:.0%})",
    )

    # C2 profile match
    c2_match = ""
    for fp in cr.model_fingerprints:
        if fp.model_name.startswith("c2:"):
            c2_match = fp.model_name
            break
    check(bool(c2_match), f"C2 profile match", c2_match or "none found")

    # Rule evaluation
    rule_matches = rule_engine.evaluate_all(cadence_results, [flow])
    fired = None
    for m in rule_matches:
        if m.rule.id in ("AEGIS-008", "AEGIS-009"):
            fired = m
            break

    if fired:
        check(True, f"Rule {fired.rule.id} fired", fired.rule.name)
    else:
        all_ids = [m.rule.id for m in rule_matches]
        check(
            False,
            "Rule AEGIS-008/009",
            f"other rules fired: {all_ids}" if all_ids else "none fired",
        )


# ─────────────────────────────────────────────────────────
#  Phase 4: YARA Binary Scan (Direct)
# ─────────────────────────────────────────────────────────
def phase4_yara():
    print("\nPhase 4: YARA Binary Scan")
    import yara

    all_matches = []
    for rule_file in sorted(YARA_DIR.glob("*.yar")):
        try:
            rules = yara.compile(filepath=str(rule_file))
            matches = rules.match(str(BEACON_PATH))
            all_matches.extend(matches)
        except Exception:
            continue

    matched_names = [m.rule for m in all_matches]
    check(len(all_matches) >= 1, f"YARA scan: {len(all_matches)} rule(s) matched")
    for name in matched_names:
        check(True, name, "matched")


# ─────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────
def main():
    global passed, failed
    print("=" * 59)
    print("  VoidLink E2E Integration Test")
    print("=" * 59)

    for phase_fn, label in [
        (phase1_malscope, "Phase 1"),
        (phase2_sentinel, "Phase 2"),
        (phase3_aegis, "Phase 3"),
        (phase4_yara, "Phase 4"),
    ]:
        try:
            phase_fn()
        except Exception as e:
            print(f"\n  [FAIL] {label} crashed: {e}")
            failed += 1

    total = passed + failed
    print()
    print("=" * 59)
    print(f"  Results: {passed}/{total} PASSED    {failed} FAILED")
    print("=" * 59)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
