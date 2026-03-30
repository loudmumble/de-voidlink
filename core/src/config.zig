//! VoidLink adversary simulation — configuration & constants
//! Magic values, syscall numbers, and timing profiles from Sysdig TRT analysis.
const std = @import("std");

// ── Magic Values (Sysdig TRT) ──────────────────────────────────────────
pub const PRCTL_MAGIC: u64 = 0x564C; // "VL"
pub const ICMP_MAGIC: u16 = 0xC0DE;
pub const XOR_KEY: u8 = 0xAA;
pub const ICMP_AUTH_KEY: u8 = 0x42;

// ── Syscall Numbers (x86_64) — reference for logging ────────────────────
pub const SYS_fork: usize = 57;
pub const SYS_prctl: usize = 157;
pub const SYS_socket: usize = 41;
pub const SYS_connect: usize = 42;
pub const SYS_recvfrom: usize = 45;
pub const SYS_write: usize = 1;
pub const SYS_memfd_create: usize = 319;
pub const SYS_execveat: usize = 322;
pub const SYS_read: usize = 0;
pub const SYS_close: usize = 3;
pub const SYS_nanosleep: usize = 35;
pub const SYS_getpid: usize = 39;
pub const SYS_kill: usize = 62;
pub const SYS_openat: usize = 257;
pub const SYS_getdents64: usize = 217;

// ── prctl / execveat / memfd constants ──────────────────────────────────
pub const PR_SET_NAME: usize = 15;
pub const AT_EMPTY_PATH: usize = 0x1000;
pub const MFD_CLOEXEC: usize = 0x0001;

// ── Socket constants ────────────────────────────────────────────────────
pub const AF_INET: usize = 2;
pub const SOCK_STREAM: usize = 1;

// ── Process masquerade names (real VoidLink samples) ────────────────────
pub const MASQUERADE_NAMES = [_][]const u8{
    "[kworker/0:0]",
    "[kworker/0:1]",
    "[kworker/u8:0]",
    "migration/0",
    "watchdog/0",
    "rcu_sched",
};

// ── C2 endpoints ────────────────────────────────────────────────────────
pub const C2_HANDSHAKE = "/api/v2/handshake";
pub const C2_SYNC = "/api/v2/sync";
pub const C2_HEARTBEAT = "/api/v2/heartbeat";
pub const C2_COMPILE = "/compile";

// ── Default C2 address ──────────────────────────────────────────────────
pub const DEFAULT_C2_ADDR = "127.0.0.1";
pub const DEFAULT_C2_PORT: u16 = 8080;

// ── Timing profiles ────────────────────────────────────────────────────
pub const Profile = struct {
    base_interval_ms: u32,
    jitter_percent: u8,
    mode: []const u8,
};

pub const PROFILE_AGGRESSIVE = Profile{
    .base_interval_ms = 4096,
    .jitter_percent = 20,
    .mode = "aggressive",
};

pub const PROFILE_PARANOID = Profile{
    .base_interval_ms = 1024,
    .jitter_percent = 30,
    .mode = "paranoid",
};

// ── Known security products ─────────────────────────────────────────────
pub const SECURITY_PRODUCTS = [_][]const u8{
    "falcon-sensor",
    "SentinelAgent",
    "cbagentd",
    "falco",
    "sysdig",
    "wazuh-agent",
    "ossec",
    "osqueryd",
    "auditd",
    "clamd",
    "AliYunDun",
    "frida-server",
};

// ── Filesystem artifact paths ───────────────────────────────────────────
pub const ARTIFACT_PATHS = [_][]const u8{
    "/tmp/.vl_",
    "/var/tmp/.vl_",
    "/dev/shm/.vl_",
    "/tmp/.font-unix/",
};

// ── Safety ──────────────────────────────────────────────────────────────
pub const SAFETY_ENV_VAR = "PHANTOM_LINK_SAFETY";

// ── JSON structured logger (writes to stderr) ───────────────────────────

pub fn jsonLog(level: []const u8, msg: []const u8, extra: []const u8) void {
    const linux = std.os.linux;
    var buf: [2048]u8 = undefined;
    const ts = std.time.timestamp();
    const output = if (extra.len > 0)
        std.fmt.bufPrint(&buf, "{{\"ts\":{d},\"level\":\"{s}\",\"msg\":\"{s}\",{s}}}\n", .{ ts, level, msg, extra }) catch return
    else
        std.fmt.bufPrint(&buf, "{{\"ts\":{d},\"level\":\"{s}\",\"msg\":\"{s}\"}}\n", .{ ts, level, msg }) catch return;
    _ = linux.syscall3(.write, 2, @intFromPtr(output.ptr), output.len);
}

pub fn jsonLogSyscall(nr: usize, name: []const u8, result: isize) void {
    var buf: [256]u8 = undefined;
    const extra = std.fmt.bufPrint(&buf,
        \\"nr":{d},"name":"{s}","result":{d}
    , .{ nr, name, result }) catch return;
    jsonLog("info", "syscall", extra);
}
