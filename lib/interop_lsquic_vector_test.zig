const std = @import("std");

const varint = @import("utils/varint.zig");
const packet_mod = @import("core/packet.zig");
const frame_mod = @import("core/frame.zig");
const core_types = @import("core/types.zig");

test "interop lsquic varint vectors" {
    const vectors = [_]struct {
        encoded: []const u8,
        value: u64,
    }{
        .{ .encoded = &[_]u8{0x25}, .value = 0x25 },
        .{ .encoded = &[_]u8{ 0x40, 0x25 }, .value = 0x25 },
        .{ .encoded = &[_]u8{ 0x9D, 0x7F, 0x3E, 0x7D }, .value = 494878333 },
        .{ .encoded = &[_]u8{ 0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C }, .value = 151288809941952652 },
    };

    for (vectors) |vector| {
        const decoded = try varint.decode(vector.encoded);
        try std.testing.expectEqual(vector.value, decoded.value);
        try std.testing.expectEqual(@as(u8, @intCast(vector.encoded.len)), decoded.len);
    }
}

test "interop lsquic version negotiation low-bit tolerance" {
    const dcid = try core_types.ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const scid = try core_types.ConnectionId.init(&[_]u8{ 9, 8, 7, 6 });

    var buf: [128]u8 = undefined;
    const vn = packet_mod.VersionNegotiationPacket{
        .dest_conn_id = dcid,
        .src_conn_id = scid,
        .supported_versions = &[_]u32{ 0x00000002, 0x00000003, core_types.QUIC_VERSION_1 },
    };

    const len = try vn.encode(&buf);
    buf[0] = 0xFF;

    var versions: [8]u32 = undefined;
    const decoded = try packet_mod.VersionNegotiationPacket.decode(buf[0..len], &versions);
    try std.testing.expectEqual(@as(usize, 3), decoded.packet.supported_versions.len);
    try std.testing.expectEqual(@as(u32, 0x00000002), decoded.packet.supported_versions[0]);
    try std.testing.expectEqual(@as(u32, 0x00000003), decoded.packet.supported_versions[1]);
    try std.testing.expectEqual(core_types.QUIC_VERSION_1, decoded.packet.supported_versions[2]);
}

test "interop lsquic version negotiation malformed vectors" {
    const dcid = try core_types.ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const scid = try core_types.ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var buf: [128]u8 = undefined;
    const vn = packet_mod.VersionNegotiationPacket{
        .dest_conn_id = dcid,
        .src_conn_id = scid,
        .supported_versions = &[_]u32{ 0x00000002, 0x00000003 },
    };
    const len = try vn.encode(&buf);

    var versions: [4]u32 = undefined;

    // Fixed bit cleared.
    var fixed_off = buf;
    fixed_off[0] &= 0xBF;
    try std.testing.expectError(error.FixedBitNotSet, packet_mod.VersionNegotiationPacket.decode(fixed_off[0..len], &versions));

    // Non-zero version marker.
    var wrong_version = buf;
    std.mem.writeInt(u32, wrong_version[1..5], core_types.QUIC_VERSION_1, .big);
    try std.testing.expectError(error.InvalidVersion, packet_mod.VersionNegotiationPacket.decode(wrong_version[0..len], &versions));

    // Version list not aligned to 4-byte entries.
    var malformed_list: [36]u8 = undefined;
    malformed_list[0] = 0xC0;
    std.mem.writeInt(u32, malformed_list[1..5], 0, .big);
    malformed_list[5] = 4;
    @memcpy(malformed_list[6..10], &[_]u8{ 1, 2, 3, 4 });
    malformed_list[10] = 4;
    @memcpy(malformed_list[11..15], &[_]u8{ 5, 6, 7, 8 });
    malformed_list[15] = 0;
    malformed_list[16] = 0;
    malformed_list[17] = 2;
    try std.testing.expectError(error.InvalidVersion, packet_mod.VersionNegotiationPacket.decode(malformed_list[0..18], &versions));

    // Oversized DCID length.
    var oversized_cid: [64]u8 = undefined;
    oversized_cid[0] = 0xC0;
    std.mem.writeInt(u32, oversized_cid[1..5], 0, .big);
    oversized_cid[5] = 21;
    @memset(oversized_cid[6..27], 0xAA);
    oversized_cid[27] = 4;
    @memcpy(oversized_cid[28..32], &[_]u8{ 9, 9, 9, 9 });
    std.mem.writeInt(u32, oversized_cid[32..36], 0x00000001, .big);
    try std.testing.expectError(error.ConnectionIdTooLong, packet_mod.VersionNegotiationPacket.decode(oversized_cid[0..36], &versions));
}

test "interop lsquic packet number reconstruction vectors" {
    const vectors = [_]struct {
        truncated: []const u8,
        largest_acked: u64,
        expected: u64,
    }{
        .{ .truncated = &[_]u8{0x41}, .largest_acked = 1, .expected = 65 },
        .{ .truncated = &[_]u8{0x02}, .largest_acked = 0, .expected = 2 },
        .{ .truncated = &[_]u8{ 0x3F, 0xFF }, .largest_acked = 1, .expected = 64 * 256 - 1 },
        .{ .truncated = &[_]u8{ 0x00, 0x3F, 0xFF, 0xFF }, .largest_acked = 1, .expected = 64 * 256 * 256 - 1 },
        .{ .truncated = &[_]u8{ 0x00, 0x01 }, .largest_acked = (1 << 16) - 1, .expected = (1 << 16) + 1 },
    };

    for (vectors) |vector| {
        const decoded = try packet_mod.PacketNumberUtil.decode(vector.truncated, vector.largest_acked);
        try std.testing.expectEqual(vector.expected, decoded);
    }
}

test "interop lsquic ack sparse range vectors" {
    var ranges_in: [256]frame_mod.AckFrame.AckRange = undefined;
    for (&ranges_in) |*range| {
        range.* = .{
            .gap = 8,
            .ack_range_length = 0,
        };
    }

    const frame = frame_mod.AckFrame{
        .largest_acked = 3_000,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ack_ranges = ranges_in[0..],
        .ecn_counts = null,
    };

    var buf: [4096]u8 = undefined;
    const len = try frame.encode(&buf);

    var ranges_out: [256]frame_mod.AckFrame.AckRange = undefined;
    const decoded = try frame_mod.AckFrame.decodeWithAckRanges(buf[0..len], &ranges_out);
    try std.testing.expectEqual(@as(usize, 256), decoded.frame.ack_ranges.len);
}

test "interop lsquic long-header truncation matrix" {
    const dcid = try core_types.ConnectionId.init(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
    const scid = try core_types.ConnectionId.init(&[_]u8{ 9, 10, 11, 12 });

    var buf: [256]u8 = undefined;
    const header = packet_mod.LongHeader{
        .packet_type = .initial,
        .version = core_types.QUIC_VERSION_1,
        .dest_conn_id = dcid,
        .src_conn_id = scid,
        .token = "retry-token",
        .payload_len = 4,
        .packet_number = 0x1234,
    };

    const len = try header.encode(&buf);
    var cut: usize = 0;
    while (cut < len) : (cut += 1) {
        try std.testing.expectError(error.UnexpectedEof, packet_mod.LongHeader.decode(buf[0..cut]));
    }
}

test "interop lsquic control-frame truncation matrix" {
    var token_buf: [128]u8 = undefined;
    const token = frame_mod.NewTokenFrame{ .token = "token-material-123" };
    const token_len = try token.encode(&token_buf);

    var cut: usize = 0;
    while (cut < token_len) : (cut += 1) {
        try std.testing.expectError(error.UnexpectedEof, frame_mod.NewTokenFrame.decode(token_buf[0..cut]));
    }

    var close_buf: [128]u8 = undefined;
    const close = frame_mod.ConnectionCloseFrame{
        .error_code = 42,
        .frame_type = 0x10,
        .reason = "transport-close",
    };
    const close_len = try close.encode(&close_buf);

    cut = 0;
    while (cut < close_len) : (cut += 1) {
        try std.testing.expectError(error.UnexpectedEof, frame_mod.ConnectionCloseFrame.decode(close_buf[0..cut]));
    }
}
