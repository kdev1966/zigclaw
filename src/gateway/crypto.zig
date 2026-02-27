//! Webhook signature verification for the gateway.
//!
//! HMAC-SHA256 verification for WhatsApp and Slack webhooks
//! with constant-time comparison to prevent timing attacks.

const std = @import("std");

/// Verify a WhatsApp webhook HMAC-SHA256 signature.
///
/// Meta sends `X-Hub-Signature-256: sha256=<hex-digest>` on every webhook POST.
/// This function computes HMAC-SHA256 over `body` using `app_secret` as the key,
/// then performs a constant-time comparison against the hex digest in the header.
///
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn verifyWhatsappSignature(body: []const u8, signature_header: []const u8, app_secret: []const u8) bool {
    if (app_secret.len == 0) return false;

    const prefix = "sha256=";
    if (!std.mem.startsWith(u8, signature_header, prefix)) return false;

    const provided_hex = signature_header[prefix.len..];
    if (provided_hex.len != 64) return false;

    const provided_bytes = hexDecode(provided_hex) orelse return false;

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var expected: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&expected, body, app_secret);

    return constantTimeEql(&expected, &provided_bytes);
}

/// Verify a Slack webhook signature (v0 scheme).
///
/// Slack sends `X-Slack-Signature: v0=<hex-digest>` and `X-Slack-Request-Timestamp`.
/// Computes HMAC-SHA256 of "v0:{timestamp}:{body}" using signing_secret,
/// with a 5-minute replay window.
pub fn verifySlackSignature(
    allocator: std.mem.Allocator,
    body: []const u8,
    timestamp_header: []const u8,
    signature_header: []const u8,
    signing_secret: []const u8,
) bool {
    if (signing_secret.len == 0) return false;
    const ts_trimmed = std.mem.trim(u8, timestamp_header, " \t\r\n");
    const sig_trimmed = std.mem.trim(u8, signature_header, " \t\r\n");
    if (!std.mem.startsWith(u8, sig_trimmed, "v0=")) return false;

    const provided_hex = sig_trimmed["v0=".len..];
    if (provided_hex.len != 64) return false;

    const ts = std.fmt.parseInt(i64, ts_trimmed, 10) catch return false;
    const now = std.time.timestamp();
    const delta = if (now >= ts) now - ts else ts - now;
    if (delta > 300) return false; // 5-minute replay window

    var base_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer base_buf.deinit(allocator);
    const bw = base_buf.writer(allocator);
    bw.print("v0:{s}:", .{ts_trimmed}) catch return false;
    bw.writeAll(body) catch return false;

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [32]u8 = undefined;
    HmacSha256.create(&mac, base_buf.items, signing_secret);

    var provided: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const hi = hexVal(provided_hex[i * 2]) orelse return false;
        const lo = hexVal(provided_hex[i * 2 + 1]) orelse return false;
        provided[i] = (hi << 4) | lo;
    }
    return constantTimeEql(&mac, &provided);
}

/// Decode a 64-char lowercase hex string into 32 bytes.
/// Returns null if any character is not a valid hex digit.
pub fn hexDecode(hex: []const u8) ?[32]u8 {
    if (hex.len != 64) return null;
    var out: [32]u8 = undefined;
    for (0..32) |i| {
        const hi = hexVal(hex[i * 2]) orelse return null;
        const lo = hexVal(hex[i * 2 + 1]) orelse return null;
        out[i] = (hi << 4) | lo;
    }
    return out;
}

/// Convert a single hex character to its 4-bit value.
pub fn hexVal(c: u8) ?u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    if (c >= 'A' and c <= 'F') return c - 'A' + 10;
    return null;
}

/// Constant-time comparison of two 32-byte arrays.
/// Always examines all bytes regardless of where a mismatch occurs.
pub fn constantTimeEql(a: *const [32]u8, b: *const [32]u8) bool {
    var diff: u8 = 0;
    for (a, b) |ab, bb| {
        diff |= ab ^ bb;
    }
    return diff == 0;
}
