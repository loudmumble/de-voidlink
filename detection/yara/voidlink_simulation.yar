/*
 * de-voidlink Simulation Binary Detection Rules
 *
 * These rules are tuned to match the phantom-beacon binary specifically,
 * using strings that are guaranteed to be present in the compiled output.
 * They serve dual purpose:
 *   1. Validate that the simulation binary IS detectable (e2e test verification)
 *   2. Provide detection signatures that also apply to real VoidLink variants
 *      that share the same endpoint paths, masquerade names, and techniques.
 *
 * For use with Malscope StaticAnalyzer (yara_rules_dir).
 */

rule VoidLink_PhantomBeacon_Confirmed {
    meta:
        description = "Confirms de-voidlink phantom-beacon binary — simulation binary with VoidLink C2 protocol and fileless execution strings"
        author = "de-voidlink detection suite"
        date = "2026-03-22"
        severity = "critical"
        mitre_attack = "T1071.001, T1027.011, T1036.004"
        target = "phantom-beacon (de-voidlink simulation binary)"

    strings:
        /* C2 protocol endpoints — hardcoded in config.zig */
        $ep_handshake  = "/api/v2/handshake" ascii
        $ep_sync       = "/api/v2/sync" ascii
        $ep_heartbeat  = "/api/v2/heartbeat" ascii
        $ep_stage1     = "/stage1.bin" ascii
        $ep_implant    = "/implant.bin" ascii

        /* Process masquerade names — hardcoded in masquerade.zig */
        $mq_kworker0   = "[kworker/0:0]" ascii
        $mq_kworker1   = "[kworker/0:1]" ascii
        $mq_kworkeru   = "[kworker/u8:0]" ascii
        $mq_migration  = "migration/0" ascii
        $mq_watchdog   = "watchdog/0" ascii
        $mq_rcu        = "rcu_sched" ascii

        /* Fileless execution logging strings — main.zig / beacon.zig */
        $s_memfd       = "memfd_create" ascii
        $s_execveat    = "execveat" ascii
        $s_voidlink_sq = "voidlink_sequence" ascii

        /* Plugin API symbol names — plugin_loader.zig string literals */
        $pl_init       = "plugin_init" ascii
        $pl_exec       = "plugin_exec" ascii
        $pl_cleanup    = "plugin_cleanup" ascii
        $pl_info       = "plugin_info" ascii

        /* Simulation-specific safety strings */
        $safety_env    = "PHANTOM_LINK_SAFETY" ascii
        $safety_dummy  = "PHANTOM_LINK_SIMULATED_PAYLOAD" ascii

        /* Zig compiler artifacts (Zig-compiled binary) */
        $zig_panic     = "reached unreachable" ascii
        $zig_overflow  = "integer overflow" ascii

        /* Beacon User-Agent */
        $ua_beacon     = "phantom-beacon/1.0" ascii

        /* Beacon session strings */
        $sess_dry      = "dry-run-session" ascii

    condition:
        uint32(0) == 0x464C457F and
        (
            /* Definitive match: C2 endpoints + masquerade = VoidLink C2 client */
            (2 of ($ep_*) and any of ($mq_*)) or

            /* Plugin API + fileless execution = VoidLink modular implant */
            (3 of ($pl_*) and any of ($s_memfd, $s_execveat, $s_voidlink_sq)) or

            /* Safety strings: simulation-specific high-confidence match */
            ($safety_env and $safety_dummy) or

            /* Beacon User-Agent or session markers + C2 endpoint */
            (($ua_beacon or $sess_dry) and any of ($ep_*)) or

            /* Zig binary with full C2 endpoint set */
            (any of ($zig_*) and 3 of ($ep_*)) or

            /* Masquerade names + plugin infrastructure */
            (2 of ($mq_*) and 2 of ($pl_*))
        )
}

rule VoidLink_DirectSyscall_Pattern {
    meta:
        description = "Detects VoidLink-style direct Linux syscall invocation: syscall numbers for memfd_create (319) and execveat (322) as immediate values in ELF binary"
        author = "de-voidlink detection suite"
        date = "2026-03-22"
        severity = "critical"
        mitre_attack = "T1106, T1027.011"
        note = "Targets the raw syscall instruction pattern used when bypassing libc. Both x86_64 syscall numbers in .text = fileless execution capability confirmed."

    strings:
        /* mov eax, 319 (memfd_create) — common encoding variants */
        $sc_memfd_b8   = { B8 3F 01 00 00 }          /* mov eax, 0x13F */
        $sc_memfd_c7c0 = { C7 C0 3F 01 00 00 }       /* mov eax, 0x13F (ModRM) */

        /* mov eax, 322 (execveat) — common encoding variants */
        $sc_execveat_b8   = { B8 42 01 00 00 }        /* mov eax, 0x142 */
        $sc_execveat_c7c0 = { C7 C0 42 01 00 00 }     /* mov eax, 0x142 (ModRM) */

        /* syscall instruction (0F 05) following the mov */
        $syscall_insn  = { 0F 05 }

        /* AT_EMPTY_PATH flag value (0x1000 = 4096) */
        $at_empty_path = { 00 10 00 00 }

        /* memfd_create syscall as 64-bit value (for Zig inline asm path) */
        $sc_memfd_64   = { 3F 01 00 00 00 00 00 00 }  /* 319 as qword */

    condition:
        uint32(0) == 0x464C457F and
        (
            /* memfd_create + execveat syscall numbers both present */
            (any of ($sc_memfd_*) and any of ($sc_execveat_*)) or

            /* memfd_create with AT_EMPTY_PATH flag (core fileless execution technique) */
            (any of ($sc_memfd_*) and $at_empty_path and $syscall_insn) or

            /* execveat with AT_EMPTY_PATH */
            (any of ($sc_execveat_*) and $at_empty_path)
        )
}

rule VoidLink_C2_Protocol_Strings {
    meta:
        description = "Detects VoidLink C2 protocol strings with camouflage content types — binary contains HTTP camouflage parsing code"
        author = "de-voidlink detection suite"
        date = "2026-03-22"
        severity = "high"
        mitre_attack = "T1001.001, T1071.001"

    strings:
        /* C2 endpoints */
        $ep_handshake = "/api/v2/handshake" ascii
        $ep_heartbeat = "/api/v2/heartbeat" ascii
        $ep_sync      = "/api/v2/sync" ascii

        /* HTTP camouflage content types used by VoidStream */
        $ct_png  = "image/png" ascii
        $ct_js   = "application/javascript" ascii
        $ct_css  = "text/css" ascii
        $ct_html = "text/html" ascii
        $ct_json = "application/json" ascii

        /* VoidStream protocol marker */
        $x_session = "X-Session-ID" ascii

        /* Beaconing interval indicators */
        $interval_str  = "base_interval_ms" ascii
        $jitter_str    = "jitter_percent" ascii

    condition:
        uint32(0) == 0x464C457F and
        (
            /* C2 endpoints + multiple camouflage types = VoidLink C2 client */
            (any of ($ep_*) and 3 of ($ct_*)) or

            /* Session header + C2 endpoints */
            ($x_session and 2 of ($ep_*)) or

            /* Beaconing timing constants + C2 */
            ($interval_str and $jitter_str and any of ($ep_*))
        )
}
