/*
 * VoidLink Runtime Artifact Detection Rules
 *
 * Detects filesystem artifacts, rootkit components, and runtime indicators.
 * Based on IOCs from Sysdig TRT + CPR reports.
 *
 * These rules are designed for scanning:
 *   - Filesystem (artifact paths)
 *   - Memory dumps (loaded modules)
 *   - Network captures (C2 traffic patterns)
 *
 * For use with Malscope analysis pipeline + Sentinel file integrity monitoring.
 */

rule VoidLink_Rootkit_LKM {
    meta:
        description = "Detects VoidLink LKM rootkit module (vl_stealth.ko)"
        author = "de-voidlink detection suite"
        date = "2026-02-19"
        reference = "https://www.sysdig.com/blog/voidlink-threat-analysis-sysdig-discovers-c2-compiled-kernel-rootkits"
        severity = "critical"
        mitre_attack = "T1014, T1547.006"
        hash_vl_stealth = "reported by Sysdig TRT"

    strings:
        /* prctl magic interface — 0x564C ("VL") */
        $prctl_magic = { 4C 56 00 00 }  /* 0x564C little-endian with padding */

        /* prctl command constants */
        $prctl_cmd_hide_port = { 01 00 00 00 }  /* cmd 1: add_hidden_port */
        $prctl_cmd_hide_pid = { 02 00 00 00 }   /* cmd 2: add_hidden_pid */
        $prctl_cmd_hide_file = { 03 00 00 00 }  /* cmd 3: add_hidden_file */
        $prctl_cmd_clear = { 04 00 00 00 }      /* cmd 4: clear_all */

        /* Kretprobe hook targets */
        $hook_tcp4 = "tcp4_seq_show" ascii
        $hook_tcp6 = "tcp6_seq_show" ascii
        $hook_udp4 = "udp4_seq_show" ascii
        $hook_netlink = "netlink_recvmsg" ascii
        $hook_diag = "inet_sk_diag_fill" ascii
        $hook_vfs = "vfs_read" ascii

        /* Module self-hiding */
        $list_del = "list_del_init" ascii
        $kobject_del = "kobject_del" ascii
        $intree = "intree" ascii

        /* Rootkit artifact path */
        $ko_path = ".font-unix/.tmp.ko" ascii
        $ko_path2 = "/tmp/.font-unix/" ascii

    condition:
        (
            /* Kernel module with rootkit indicators */
            (uint32(0) == 0x464C457F and 3 of ($hook_*)) or
            /* prctl magic with hook targets and commands */
            ($prctl_magic and 2 of ($hook_*)) or
            /* prctl command constants with magic */
            ($prctl_magic and any of ($prctl_cmd_*)) or
            /* Self-hiding module with intree spoofing */
            ($list_del and $kobject_del and $intree) or
            /* Self-hiding module with hooks */
            ($list_del and $kobject_del and any of ($hook_*)) or
            /* Rootkit artifact paths */
            (any of ($ko_path*) and any of ($hook_*))
        )
}

rule VoidLink_eBPF_Rootkit {
    meta:
        description = "Detects VoidLink eBPF rootkit component (hide_ss.bpf.o)"
        author = "de-voidlink detection suite"
        date = "2026-02-19"
        reference = "https://www.sysdig.com/blog/voidlink-threat-analysis-sysdig-discovers-c2-compiled-kernel-rootkits"
        severity = "critical"
        mitre_attack = "T1014"

    strings:
        /* eBPF map names used by VoidLink */
        $map_ports = "sd_nl_ports" ascii
        $map_pids = "sd_cg_pids" ascii
        $map_names = "sd_cg_names" ascii

        /* BPF program section names */
        $sec_kprobe = "kprobe/" ascii
        $sec_kretprobe = "kretprobe/" ascii
        $sec_tracepoint = "tracepoint/" ascii

        /* eBPF-specific syscall patterns */
        $bpf_prog_load = "bpf_prog_load" ascii
        $bpf_map_create = "bpf_map_create" ascii

    condition:
        (
            /* eBPF object with VoidLink map names */
            (any of ($map_*) and any of ($sec_*)) or
            /* Multiple VoidLink-specific map names */
            (2 of ($map_*)) or
            /* BPF program loading with VoidLink maps */
            (any of ($bpf_*) and any of ($map_*))
        )
}

rule VoidLink_ICMP_Covert_Channel {
    meta:
        description = "Detects VoidLink ICMP covert channel control script"
        author = "de-voidlink detection suite"
        date = "2026-02-19"
        reference = "https://www.sysdig.com/blog/voidlink-threat-analysis-sysdig-discovers-c2-compiled-kernel-rootkits"
        severity = "high"
        mitre_attack = "T1095, T1573"

    strings:
        /* ICMP magic values */
        $icmp_magic_hex = "0xC0DE" ascii nocase
        $icmp_auth_hex = "0x42" ascii

        /* ICMP command constants (from Sysdig report) */
        $cmd_hide_pid = "HIDE_PID" ascii
        $cmd_hide_port = "HIDE_PORT" ascii
        $cmd_hide_file = "HIDE_FILE" ascii
        $cmd_show_mod = "SHOW_MOD" ascii
        $cmd_self_destruct = "SELF_DESTRUCT" ascii
        $cmd_hide_ip = "HIDE_IP" ascii

        /* Command byte values (padded with ICMP magic prefix 0xC0DE for anchoring) */
        $cmd_byte_01 = { C0 DE 01 }  /* magic + HIDE_PID */
        $cmd_byte_02 = { C0 DE 02 }  /* magic + HIDE_PORT */
        $cmd_byte_fe = { C0 DE FE }  /* magic + SELF_DESTRUCT */
        $cmd_byte_ff = { C0 DE FF }  /* magic + CLEAR */

        /* Python ICMP control script indicators */
        $scapy_import = "from scapy" ascii
        $icmp_type = "ICMP" ascii
        $raw_socket = "SOCK_RAW" ascii

    condition:
        (
            /* ICMP control script with VoidLink magic and auth */
            ($icmp_magic_hex and $icmp_auth_hex and 2 of ($cmd_*)) or
            /* ICMP magic with command names */
            ($icmp_magic_hex and 2 of ($cmd_*)) or
            /* Python script with ICMP and VoidLink commands */
            ($scapy_import and $icmp_type and any of ($cmd_hide_*, $cmd_self_destruct)) or
            /* Raw socket ICMP channel */
            ($raw_socket and $icmp_magic_hex)
        )
}

rule VoidLink_Filesystem_Artifacts {
    meta:
        description = "Detects VoidLink filesystem artifact patterns in file content or paths"
        author = "de-voidlink detection suite"
        date = "2026-02-19"
        severity = "high"
        mitre_attack = "T1036.005"

    strings:
        /* VoidLink artifact paths */
        $path_tmp_vl = "/tmp/.vl_" ascii
        $path_var_vl = "/var/tmp/.vl_" ascii
        $path_shm_vl = "/dev/shm/.vl_" ascii
        $path_font = "/tmp/.font-unix/" ascii

        /* Self-destruct indicators */
        $hist_clear = "history -c" ascii
        $log_wipe = "rm -f /var/log/" ascii
        $shred = "shred" ascii
        $unlink_self = "unlink(" ascii

    condition:
        (
            /* Multiple VoidLink artifact paths */
            (2 of ($path_*)) or
            /* Anti-forensics with artifact paths */
            (any of ($path_*) and any of ($hist_clear, $log_wipe, $shred, $unlink_self))
        )
}

rule VoidLink_SRC_Request {
    meta:
        description = "Detects Serverside Rootkit Compilation (SRC) request pattern"
        author = "de-voidlink detection suite"
        date = "2026-02-19"
        reference = "https://www.sysdig.com/blog/voidlink-threat-analysis-sysdig-discovers-c2-compiled-kernel-rootkits"
        severity = "critical"
        mitre_attack = "T1587.001"

    strings:
        /* SRC request JSON fields */
        $kernel_release = "kernel_release" ascii
        $hidden_ports = "hidden_ports" ascii
        $has_gcc = "has_gcc" ascii

        /* Compile endpoint */
        $compile_ep = "/compile" ascii

        /* init_module syscall pattern */
        $init_module = "init_module" ascii
        $finit_module = "finit_module" ascii

    condition:
        (
            /* SRC request with compile endpoint and all fields */
            ($compile_ep and $kernel_release and $hidden_ports and $has_gcc) or
            /* SRC request with compile endpoint */
            ($compile_ep and $kernel_release and $hidden_ports) or
            /* Module loading with compile request */
            (any of ($init_module, $finit_module) and $compile_ep)
        )
}
