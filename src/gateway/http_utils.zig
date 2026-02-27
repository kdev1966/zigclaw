//! HTTP parsing utilities for the gateway.
//!
//! Query parameter extraction, header parsing, bearer token validation,
//! and readiness endpoint logic.

const std = @import("std");
const health = @import("../health.zig");
const PairingGuard = @import("../security/pairing.zig").PairingGuard;

/// Readiness response — encapsulates HTTP status and body for /ready.
pub const ReadyResponse = struct {
    http_status: []const u8,
    body: []const u8,
    /// Whether body was allocated and should be freed by caller.
    allocated: bool,
};

/// Handle the /ready endpoint logic. Queries the global health registry
/// and returns the appropriate HTTP status and JSON body.
/// If `allocated` is true in the result, the caller owns `body` memory.
pub fn handleReady(allocator: std.mem.Allocator) ReadyResponse {
    const readiness = health.checkRegistryReadiness(allocator) catch {
        return .{
            .http_status = "500 Internal Server Error",
            .body = "{\"status\":\"not_ready\",\"checks\":[]}",
            .allocated = false,
        };
    };
    const json_body = readiness.formatJson(allocator) catch {
        if (readiness.checks.len > 0) {
            allocator.free(readiness.checks);
        }
        return .{
            .http_status = "500 Internal Server Error",
            .body = "{\"status\":\"not_ready\",\"checks\":[]}",
            .allocated = false,
        };
    };
    if (readiness.checks.len > 0) {
        allocator.free(readiness.checks);
    }
    return .{
        .http_status = if (readiness.status == .ready) "200 OK" else "503 Service Unavailable",
        .body = json_body,
        .allocated = true,
    };
}

/// Extract a query parameter value from a URL target string.
/// e.g. parseQueryParam("/whatsapp?hub.mode=subscribe&hub.challenge=abc", "hub.challenge") => "abc"
/// Returns null if the parameter is not found.
pub fn parseQueryParam(target: []const u8, name: []const u8) ?[]const u8 {
    const qmark = std.mem.indexOf(u8, target, "?") orelse return null;
    var query = target[qmark + 1 ..];

    while (query.len > 0) {
        const amp = std.mem.indexOf(u8, query, "&") orelse query.len;
        const pair = query[0..amp];

        const eq = std.mem.indexOf(u8, pair, "=");
        if (eq) |eq_pos| {
            const key = pair[0..eq_pos];
            const value = pair[eq_pos + 1 ..];
            if (std.mem.eql(u8, key, name)) return value;
        }

        if (amp < query.len) {
            query = query[amp + 1 ..];
        } else {
            break;
        }
    }
    return null;
}

/// Validate a bearer token against a list of paired tokens.
/// Returns true if paired_tokens is empty (backwards compat) or token matches.
pub fn validateBearerToken(token: []const u8, paired_tokens: []const []const u8) bool {
    if (paired_tokens.len == 0) return true;
    for (paired_tokens) |pt| {
        if (std.mem.eql(u8, token, pt)) return true;
    }
    return false;
}

/// Extract the value of a named header from raw HTTP bytes.
/// Searches for "Name: value\r\n" (case-insensitive name match).
pub fn extractHeader(raw: []const u8, name: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (pos + 1 < raw.len) {
        if (raw[pos] == '\r' and raw[pos + 1] == '\n') {
            pos += 2;
            break;
        }
        pos += 1;
    }

    while (pos < raw.len) {
        const line_end = std.mem.indexOf(u8, raw[pos..], "\r\n") orelse break;
        const line = raw[pos .. pos + line_end];
        if (line.len == 0) break;

        if (line.len > name.len and line[name.len] == ':') {
            const header_name = line[0..name.len];
            if (asciiEqlIgnoreCase(header_name, name)) {
                var val_start: usize = name.len + 1;
                while (val_start < line.len and line[val_start] == ' ') val_start += 1;
                return line[val_start..];
            }
        }

        pos += line_end + 2;
    }
    return null;
}

/// Extract the bearer token from an Authorization header value.
/// "Bearer <token>" -> "<token>", or null if format doesn't match.
pub fn extractBearerToken(auth_header: []const u8) ?[]const u8 {
    const prefix = "Bearer ";
    if (auth_header.len > prefix.len and std.mem.startsWith(u8, auth_header, prefix)) {
        return auth_header[prefix.len..];
    }
    return null;
}

/// Returns true when a webhook request should be accepted for the current
/// pairing state and bearer token. Missing pairing state fails closed.
pub fn isWebhookAuthorized(pairing_guard: ?*const PairingGuard, bearer_token: ?[]const u8) bool {
    const guard = pairing_guard orelse return false;
    if (!guard.requirePairing()) return true;
    const token = bearer_token orelse return false;
    return guard.isAuthenticated(token);
}

/// Format the /pair success payload. Returns null when buffer is too small.
pub fn formatPairSuccessResponse(buf: []u8, token: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, "{{\"status\":\"paired\",\"token\":\"{s}\"}}", .{token}) catch null;
}

/// Case-insensitive ASCII comparison.
pub fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        const al = if (ac >= 'A' and ac <= 'Z') ac + 32 else ac;
        const bl = if (bc >= 'A' and bc <= 'Z') bc + 32 else bc;
        if (al != bl) return false;
    }
    return true;
}

// ── Tests ────────────────────────────────────────────────────────

test "parseQueryParam extracts single param" {
    const val = parseQueryParam("/whatsapp?hub.mode=subscribe", "hub.mode");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("subscribe", val.?);
}

test "parseQueryParam extracts param from multiple" {
    const target = "/whatsapp?hub.mode=subscribe&hub.verify_token=mytoken&hub.challenge=abc123";
    try std.testing.expectEqualStrings("subscribe", parseQueryParam(target, "hub.mode").?);
    try std.testing.expectEqualStrings("mytoken", parseQueryParam(target, "hub.verify_token").?);
    try std.testing.expectEqualStrings("abc123", parseQueryParam(target, "hub.challenge").?);
}

test "parseQueryParam returns null for missing param" {
    const val = parseQueryParam("/whatsapp?hub.mode=subscribe", "hub.challenge");
    try std.testing.expect(val == null);
}

test "parseQueryParam returns null for no query string" {
    const val = parseQueryParam("/whatsapp", "hub.mode");
    try std.testing.expect(val == null);
}

test "parseQueryParam empty value" {
    const val = parseQueryParam("/path?key=", "key");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("", val.?);
}

test "parseQueryParam partial key match does not match" {
    const val = parseQueryParam("/path?hub.mode_extra=subscribe", "hub.mode");
    try std.testing.expect(val == null);
}

test "validateBearerToken allows when no paired tokens" {
    try std.testing.expect(validateBearerToken("anything", &.{}));
}

test "validateBearerToken allows valid token" {
    const tokens = &[_][]const u8{ "token-a", "token-b", "token-c" };
    try std.testing.expect(validateBearerToken("token-b", tokens));
}

test "validateBearerToken rejects invalid token" {
    const tokens = &[_][]const u8{ "token-a", "token-b" };
    try std.testing.expect(!validateBearerToken("token-c", tokens));
}

test "validateBearerToken rejects empty token when tokens configured" {
    const tokens = &[_][]const u8{"secret"};
    try std.testing.expect(!validateBearerToken("", tokens));
}

test "validateBearerToken exact match required" {
    const tokens = &[_][]const u8{"abc123"};
    try std.testing.expect(validateBearerToken("abc123", tokens));
    try std.testing.expect(!validateBearerToken("abc1234", tokens));
    try std.testing.expect(!validateBearerToken("abc12", tokens));
}

test "isWebhookAuthorized fails closed when pairing guard missing" {
    try std.testing.expect(!isWebhookAuthorized(null, "token"));
}

test "isWebhookAuthorized allows when pairing disabled" {
    var guard = try PairingGuard.init(std.testing.allocator, false, &.{});
    defer guard.deinit();
    try std.testing.expect(isWebhookAuthorized(&guard, null));
}

test "isWebhookAuthorized requires valid bearer token when pairing enabled" {
    const tokens = [_][]const u8{"zc_valid"};
    var guard = try PairingGuard.init(std.testing.allocator, true, &tokens);
    defer guard.deinit();

    try std.testing.expect(isWebhookAuthorized(&guard, "zc_valid"));
    try std.testing.expect(!isWebhookAuthorized(&guard, null));
    try std.testing.expect(!isWebhookAuthorized(&guard, "zc_invalid"));
}

test "formatPairSuccessResponse includes paired token" {
    var buf: [256]u8 = undefined;
    const response = formatPairSuccessResponse(&buf, "zc_token_123") orelse unreachable;
    try std.testing.expectEqualStrings(
        "{\"status\":\"paired\",\"token\":\"zc_token_123\"}",
        response,
    );
}

test "formatPairSuccessResponse fails when buffer is too small" {
    var buf: [8]u8 = undefined;
    try std.testing.expect(formatPairSuccessResponse(&buf, "zc_token_123") == null);
}

test "extractHeader finds Authorization header" {
    const raw = "POST /webhook HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret123\r\nContent-Type: application/json\r\n\r\n";
    const val = extractHeader(raw, "Authorization");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("Bearer secret123", val.?);
}

test "extractHeader case insensitive" {
    const raw = "GET /health HTTP/1.1\r\ncontent-type: text/plain\r\n\r\n";
    const val = extractHeader(raw, "Content-Type");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("text/plain", val.?);
}

test "extractHeader returns null for missing header" {
    const raw = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const val = extractHeader(raw, "Authorization");
    try std.testing.expect(val == null);
}

test "extractHeader returns null for empty headers" {
    const raw = "GET / HTTP/1.1\r\n\r\n";
    try std.testing.expect(extractHeader(raw, "Host") == null);
}

test "extractBearerToken extracts token" {
    try std.testing.expectEqualStrings("mytoken", extractBearerToken("Bearer mytoken").?);
}

test "extractBearerToken returns null for non-Bearer" {
    try std.testing.expect(extractBearerToken("Basic abc123") == null);
}

test "extractBearerToken returns null for empty string" {
    try std.testing.expect(extractBearerToken("") == null);
}

test "extractBearerToken returns null for just Bearer" {
    try std.testing.expect(extractBearerToken("Bearer") == null);
}
