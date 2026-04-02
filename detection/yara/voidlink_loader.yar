/*
 * VoidLink Loader Detection Rules
 *
 * Detects Stage 0 (dropper) and Stage 1 (downloader) VoidLink components.
 * Based on IOCs from:
 *   - Check Point Research: VoidLink Cloud-Native Malware Framework (Jan 2026)
 *   - Sysdig TRT: VoidLink Threat Analysis (Jan 2026)
 *   - Ontinue: Dissecting an AI-Generated C2 Implant (Jan 2026)
 *
 * For use with Malscope static analysis pipeline.
 */

rule VoidLink_Stage0_Dropper {
    meta:
        description = "Detects VoidLink Stage 0 dropper — fileless execution via memfd_create + execveat"
        author = "de-voidlink detection suite"
        date = "2026-02-19"
        reference = "https://www.sysdig.com/blog/voidlink-threat-analysis-sysdig-discovers-c2-compiled-kernel-rootkits"
        severity = "critical"
        mitre_attack = "T1059.004, T1106"

    strings:
        /* memfd_create syscall — fileless execution signature */
        $memfd_name = "memfd_create" ascii  /* memfd_create function reference */

        /* XOR encoding key used for C2 config */
        $xor_key = { AA AA AA AA }

        /* C2 endpoint strings */
        $c2_handshake = "/api/v2/handshake" ascii
        $c2_sync = "/api/v2/sync" ascii
        $c2_heartbeat = "/api/v2/heartbeat" ascii

        /* Process masquerade names */
        $kworker_0 = "[kworker/0:0]" ascii
        $kworker_1 = "[kworker/0:1]" ascii
        $kworker_u = "[kworker/u8:0]" ascii
        $migration = "migration/0" ascii
        $watchdog = "watchdog/0" ascii
        $rcu = "rcu_sched" ascii

        /* Syscall number sequences (x86_64 little-endian) in .text */
        $sys_memfd = { C7 ?? 3F 01 00 00 }   /* mov r/m, 319 (memfd_create) */
        $sys_execveat = { C7 ?? 42 01 00 00 } /* mov r/m, 322 (execveat) */

        /* AT_EMPTY_PATH flag for execveat */
        $at_empty_path = { 00 10 00 00 }  /* 0x1000 */

    condition:
        uint32(0) == 0x464C457F and  /* ELF magic */
        (
            /* Core pattern: memfd + execveat execution path */
            (2 of ($sys_memfd, $sys_execveat, $at_empty_path)) or
            /* Fileless execution with empty name */
            ($memfd_name and $sys_memfd) or
            /* XOR-encoded config with syscall patterns */
            ($xor_key and any of ($sys_*)) or
            /* C2 communication strings */
            (2 of ($c2_*)) or
            /* Process masquerade with C2 endpoints */
            (any of ($kworker_*, $migration, $watchdog, $rcu) and any of ($c2_*))
        )
}

rule VoidLink_Stage0_XOR_Config {
    meta:
        description = "Detects XOR-encoded configuration blob (key 0xAA) typical of VoidLink Stage 0"
        author = "de-voidlink detection suite"
        date = "2026-02-19"
        reference = "https://www.sysdig.com/blog/voidlink-threat-analysis-sysdig-discovers-c2-compiled-kernel-rootkits"
        severity = "high"
        mitre_attack = "T1027"

    strings:
        /* XOR 0xAA encoded common strings */
        /* "http" XOR 0xAA = \xc2\xc2\xc2\xc6 — not useful, use pattern instead */

        /* Port byte-swap pattern (rolw $8, %cx) */
        $port_swap = { 66 C1 C1 08 }  /* rolw $8, %cx */

        /* XOR decode loop pattern */
        $xor_loop = { 34 AA }  /* xor al, 0xAA */

        /* C2 IP pattern (8.149.128.10 in various encodings) */
        $c2_ip_str = "8.149.128.10" ascii
        $c2_ip_xor = { 92 84 9B 9E 93 84 9B 98 92 84 9B 9A }  /* "8.149.128.10" XOR 0xAA */

    condition:
        uint32(0) == 0x464C457F and
        (
            ($port_swap and $xor_loop) or
            $c2_ip_str or
            $c2_ip_xor
        )
}

rule VoidLink_Stage1_Downloader {
    meta:
        description = "Detects VoidLink Stage 1 binary that downloads the full implant"
        author = "de-voidlink detection suite"
        date = "2026-02-19"
        severity = "critical"
        mitre_attack = "T1105"

    strings:
        $stage1_path = "/stage1.bin" ascii
        $implant_path = "/implant.bin" ascii
        $compile_endpoint = "/compile" ascii

        /* User-Agent strings used by VoidLink */
        $ua_chrome = "Chrome/120.0.0.0 Safari/537.36" ascii
        $ua_firefox = "Firefox/121.0" ascii
        $ua_googlebot = "Googlebot/2.1" ascii
        $ua_curl = "curl/8.4.0" ascii

        /* VoidLink prctl magic "VL" = 0x564C */
        $prctl_magic = { 4C 56 }  /* "VL" little-endian */
        $prctl_magic_be = { 56 4C }  /* "VL" big-endian */

    condition:
        uint32(0) == 0x464C457F and
        (
            ($stage1_path or $implant_path) or
            ($compile_endpoint and any of ($ua_*)) or
            (any of ($prctl_magic*) and any of ($ua_*))
        )
}
