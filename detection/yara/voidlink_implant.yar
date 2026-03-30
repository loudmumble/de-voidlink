/*
 * VoidLink Implant Detection Rules
 *
 * Detects the core VoidLink implant (Zig-compiled ELF binary).
 * Targets structural characteristics from Ontinue + CPR analysis:
 *   - Zig compiler artifacts
 *   - AI code generation indicators (Phase labels, _v3 versioning)
 *   - Plugin API strings
 *   - Module registry patterns
 *   - High entropy sections (runtime encryption)
 *
 * For use with Malscope static analysis pipeline.
 */

rule VoidLink_Implant_Zig {
    meta:
        description = "Detects VoidLink core implant — Zig-compiled ELF with characteristic module names"
        author = "de-voidlink detection suite"
        date = "2026-02-19"
        reference = "https://www.ontinue.com/resource/voidlink-dissecting-an-ai-generated-c2-implant/"
        severity = "critical"
        mitre_attack = "T1059, T1106"

    strings:
        /* Module registry names (from Ontinue analysis) */
        $mod_task_router = "task_router" ascii
        $mod_stealth = "stealth_manager" ascii
        $mod_injection = "injection_manager" ascii
        $mod_debugger = "debugger_detector" ascii

        /* Plugin infrastructure strings */
        $plugin_init = "plugin_init" ascii
        $plugin_exec = "plugin_exec" ascii
        $plugin_cleanup = "plugin_cleanup" ascii
        $plugin_info = "plugin_info" ascii

        /* AI code generation indicators (from Ontinue) */
        $phase1 = "Phase 1:" ascii
        $phase2 = "Phase 2:" ascii
        $phase3 = "Phase 3:" ascii
        $phase4 = "Phase 4:" ascii
        $phase5 = "Phase 5:" ascii
        $phase6 = "Phase 6:" ascii
        $phase8 = "Phase 8:" ascii

        /* VoidLink-specific strings */
        $voidstream = "VoidStream" ascii
        $voidlink = "VoidLink" ascii
        $vl_prefix = ".vl_" ascii

        /* Zig compiler artifacts */
        $zig_panic = "panic: " ascii
        $zig_unreachable = "reached unreachable" ascii
        $zig_overflow = "integer overflow" ascii

        /* _v3 versioning pattern (AI indicator) */
        $v3_suffix = /_v3\x00/ ascii

        /* Comment separator pattern (AI indicator — excessive "=====" blocks) */
        $separator = "=====" ascii

    condition:
        uint32(0) == 0x464C457F and
        (
            /* Module registry detection */
            (2 of ($mod_*)) or
            /* Plugin API presence */
            (3 of ($plugin_*)) or
            /* AI generation indicators with VoidLink strings */
            (3 of ($phase*) and any of ($voidstream, $voidlink, $vl_prefix)) or
            /* Zig binary with VoidLink characteristics */
            (any of ($zig_*) and any of ($voidstream, $voidlink) and any of ($mod_*)) or
            /* AI version suffix pattern with VoidLink strings */
            ($v3_suffix and any of ($voidstream, $voidlink, $vl_prefix)) or
            /* AI comment separators with phase labels */
            ($separator and 2 of ($phase*))
        )
}

rule VoidLink_Implant_HighEntropy {
    meta:
        description = "Detects ELF binary with suspicious high-entropy sections (runtime encryption)"
        author = "de-voidlink detection suite"
        date = "2026-02-19"
        reference = "https://www.ontinue.com/resource/voidlink-dissecting-an-ai-generated-c2-implant/"
        severity = "high"
        mitre_attack = "T1027.002"
        note = "VoidLink implant measured at 7.24/8.0 entropy by Ontinue. Threshold set at 7.0."

    strings:
        /* AES-256-GCM related strings */
        $aes_gcm = "AES-256-GCM" ascii nocase
        $aes_key = "aes_key" ascii
        $gcm_nonce = "nonce" ascii

        /* Encryption-related function patterns */
        $encrypt = "encrypt" ascii
        $decrypt = "decrypt" ascii

    condition:
        uint32(0) == 0x464C457F and
        /* Binary size consistent with VoidLink implant (800KB - 5MB) */
        filesize > 800KB and filesize < 5MB and
        /* Math section entropy heuristic: look for encrypted sections */
        (
            (any of ($aes_*, $gcm_*) and any of ($encrypt, $decrypt)) or
            /* Large binary with very few readable strings suggests packed/encrypted */
            (filesize > 1MB and #encrypt == 0 and #decrypt == 0)
        )
}

rule VoidLink_Implant_CloudFingerprint {
    meta:
        description = "Detects cloud provider fingerprinting code typical of VoidLink"
        author = "de-voidlink detection suite"
        date = "2026-02-19"
        reference = "https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/"
        severity = "high"
        mitre_attack = "T1082, T1580"

    strings:
        /* Cloud metadata API URLs */
        $aws_meta = "169.254.169.254" ascii
        $aws_token = "latest/api/token" ascii
        $gcp_meta = "metadata.google.internal" ascii
        $azure_meta = "169.254.169.254/metadata" ascii
        $alibaba_meta = "100.100.100.200" ascii

        /* Cloud credential environment variables */
        $aws_key = "AWS_ACCESS_KEY" ascii
        $aws_secret = "AWS_SECRET_ACCESS_KEY" ascii
        $gcp_project = "GOOGLE_CLOUD_PROJECT" ascii
        $azure_sub = "AZURE_SUBSCRIPTION_ID" ascii

        /* Container/K8s detection */
        $dockerenv = "/.dockerenv" ascii
        $k8s_sa = "/var/run/secrets/kubernetes.io" ascii
        $k8s_ns = "KUBERNETES_SERVICE_HOST" ascii

    condition:
        uint32(0) == 0x464C457F and
        (
            /* Multi-cloud fingerprinting */
            (3 of ($aws_*, $gcp_*, $azure_*, $alibaba_*)) or
            /* Cloud + container detection */
            (any of ($aws_meta, $gcp_meta, $azure_meta) and any of ($dockerenv, $k8s_*)) or
            /* Cloud credential harvesting */
            (2 of ($aws_key, $aws_secret, $gcp_project, $azure_sub) and any of ($k8s_*))
        )
}
