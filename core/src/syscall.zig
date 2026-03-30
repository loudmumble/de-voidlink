//! Direct Linux syscall wrappers — NO libc.
//! Replicates VoidLink's exact syscall interface for Sentinel detection.
const std = @import("std");
const linux = std.os.linux;

// ── Types ───────────────────────────────────────────────────────────────

pub const Timespec = extern struct {
    sec: i64,
    nsec: i64,
};

pub const SockaddrIn = extern struct {
    family: u16 = 2, // AF_INET
    port: u16, // network byte order
    addr: u32, // network byte order
    zero: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0 },

    pub fn init(addr_u32: u32, port: u16) SockaddrIn {
        return .{
            .port = std.mem.nativeToBig(u16, port),
            .addr = std.mem.nativeToBig(u32, addr_u32),
        };
    }
};

// ── Syscall wrappers ────────────────────────────────────────────────────

/// fork(2) — syscall 57
pub fn sys_fork() isize {
    return @bitCast(linux.syscall0(.fork));
}

/// prctl(2) — syscall 157
pub fn sys_prctl(option: usize, arg2: usize) isize {
    return @bitCast(linux.syscall2(.prctl, option, arg2));
}

/// socket(2) — syscall 41
pub fn sys_socket(domain: usize, stype: usize, protocol: usize) isize {
    return @bitCast(linux.syscall3(.socket, domain, stype, protocol));
}

/// connect(2) — syscall 42
pub fn sys_connect(fd: usize, addr: [*]const u8, addrlen: usize) isize {
    return @bitCast(linux.syscall3(.connect, fd, @intFromPtr(addr), addrlen));
}

/// recvfrom(2) — syscall 45  (src_addr=0, addrlen=0 for connected TCP)
pub fn sys_recvfrom(fd: usize, buf: [*]u8, len: usize, flags: usize) isize {
    return @bitCast(linux.syscall6(.recvfrom, fd, @intFromPtr(buf), len, flags, 0, 0));
}

/// write(2) — syscall 1
pub fn sys_write_syscall(fd: usize, buf: [*]const u8, count: usize) isize {
    return @bitCast(linux.syscall3(.write, fd, @intFromPtr(buf), count));
}

/// read(2) — syscall 0
pub fn sys_read(fd: usize, buf: [*]u8, count: usize) isize {
    return @bitCast(linux.syscall3(.read, fd, @intFromPtr(buf), count));
}

/// memfd_create(2) — syscall 319
pub fn sys_memfd_create(name: [*:0]const u8, flags: usize) isize {
    return @bitCast(linux.syscall2(.memfd_create, @intFromPtr(name), flags));
}

/// close(2) — syscall 3
pub fn sys_close(fd: usize) isize {
    return @bitCast(linux.syscall1(.close, fd));
}

/// nanosleep(2) — syscall 35
pub fn sys_nanosleep(req: *const Timespec) isize {
    return @bitCast(linux.syscall2(.nanosleep, @intFromPtr(req), 0));
}

/// getpid(2) — syscall 39
pub fn sys_getpid() isize {
    return @bitCast(linux.syscall0(.getpid));
}

/// exit(2) — syscall 60
pub fn sys_exit(code: usize) noreturn {
    _ = linux.syscall1(.exit, code);
    unreachable;
}

/// openat(2) — syscall 257 (used with AT_FDCWD for open-like behavior)
pub fn sys_openat(dirfd: usize, path: [*:0]const u8, flags: usize, mode: usize) isize {
    return @bitCast(linux.syscall4(.openat, dirfd, @intFromPtr(path), flags, mode));
}

/// mmap(2) — syscall 9
pub fn sys_mmap(addr: usize, len: usize, prot: usize, flags: usize, fd: usize, offset: usize) isize {
    return @bitCast(linux.syscall6(.mmap, addr, len, prot, flags, fd, offset));
}

/// mprotect(2) — syscall 10
pub fn sys_mprotect(addr: usize, len: usize, prot: usize) isize {
    return @bitCast(linux.syscall3(.mprotect, addr, len, prot));
}

/// munmap(2) — syscall 11
pub fn sys_munmap(addr: usize, len: usize) isize {
    return @bitCast(linux.syscall2(.munmap, addr, len));
}

/// execveat(2) — syscall 322
pub fn sys_execveat(fd: usize, path: [*:0]const u8, argv: usize, envp: usize, flags: usize) isize {
    return @bitCast(linux.syscall5(.execveat, fd, @intFromPtr(path), argv, envp, flags));
}

/// wait4(2) — syscall 61 (reap child process)
pub fn sys_wait4(pid: isize, status: ?*i32, options: usize) isize {
    return @bitCast(linux.syscall4(
        .wait4,
        @as(usize, @bitCast(pid)),
        if (status) |s| @intFromPtr(s) else 0,
        options,
        0, // rusage = NULL
    ));
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Sleep for `ms` milliseconds using raw nanosleep syscall.
pub fn sleepMs(ms: u64) void {
    const req = Timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
    _ = sys_nanosleep(&req);
}

/// Parse dotted-quad IPv4 string to host-byte-order u32.
pub fn parseIpv4(addr: []const u8) !u32 {
    var result: u32 = 0;
    var octet: u32 = 0;
    var dots: u8 = 0;
    for (addr) |c| {
        if (c == '.') {
            if (octet > 255 or dots >= 4) return error.InvalidAddress;
            result = (result << 8) | octet;
            octet = 0;
            dots += 1;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + @as(u32, c - '0');
        } else {
            return error.InvalidAddress;
        }
    }
    if (dots != 3 or octet > 255) return error.InvalidAddress;
    result = (result << 8) | octet;
    return result;
}
