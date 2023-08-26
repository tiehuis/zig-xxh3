const std = @import("std");
const assert = std.debug.assert;
const rotl = std.math.rotl;

const SEC_ALIGN = 64;
const SECRET_SIZE_MIN = 136;
const SECRET_DEFAULT_SIZE = 192;
comptime {
    assert(SECRET_DEFAULT_SIZE >= SECRET_SIZE_MIN);
}

const STRIPE_LEN = 64;
const SECRET_CONSUME_RATE = 8;
const ACC_NB = STRIPE_LEN / @sizeOf(u64);
const PREFETCH_DIST = 256; // use std.prefetch

const DEFAULT_SECRET: [SECRET_DEFAULT_SIZE]u8 align(SEC_ALIGN) = .{
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
};

const PRIME_MX1 = 0x165667919E3779F9; // 0b0001011001010110011001111001000110011110001101110111100111111001
const PRIME_MX2 = 0x9FB21C651E98DF25; // 0b1001111110110010000111000110010100011110100110001101111100100101

const PRIME32_1 = 0x9E3779B1; // 0b10011110001101110111100110110001
const PRIME32_2 = 0x85EBCA77; // 0b10000101111010111100101001110111
const PRIME32_3 = 0xC2B2AE3D; // 0b11000010101100101010111000111101
const PRIME32_4 = 0x27D4EB2F; // 0b00100111110101001110101100101111
const PRIME32_5 = 0x165667B1; // 0b00010110010101100110011110110001

const PRIME64_1 = 0x9E3779B185EBCA87; // 0b1001111000110111011110011011000110000101111010111100101010000111
const PRIME64_2 = 0xC2B2AE3D27D4EB4F; // 0b1100001010110010101011100011110100100111110101001110101101001111
const PRIME64_3 = 0x165667B19E3779F9; // 0b0001011001010110011001111011000110011110001101110111100111111001
const PRIME64_4 = 0x85EBCA77C2B2AE63; // 0b1000010111101011110010100111011111000010101100101010111001100011
const PRIME64_5 = 0x27D4EB2F165667C5; // 0b0010011111010100111010110010111100010110010101100110011111000101

// Core

fn readIntLittle(comptime T: type, buf: []const u8) T {
    return std.mem.readIntLittle(T, &buf[0..@sizeOf(T)].*);
}

inline fn mul32to64(lhs: u32, rhs: u32) u64 {
    const l: u64 = lhs;
    const r: u64 = rhs;
    return l *% r;
}

inline fn mul32to64_add64(lhs: u64, rhs: u64, acc: u64) u64 {
    return mul32to64(@truncate(lhs), @truncate(rhs)) +% acc;
}

inline fn mul128_fold64(lo: u64, hi: u64) u64 {
    const p = @as(u128, lo) * hi;
    const p_hi: u64 = @truncate(p >> 64);
    const p_lo: u64 = @truncate(p);
    return p_lo ^ p_hi;
}

inline fn xxh64_avalanche(h_: u64) u64 {
    var h = h_;
    h ^= h >> 33;
    h *%= PRIME64_2;
    h ^= h >> 29;
    h *%= PRIME64_3;
    h ^= h >> 32;
    return h;
}

inline fn xxh3_avalanche(h_: u64) u64 {
    var h = h_;
    h ^= h >> 37;
    h *%= PRIME_MX1;
    h ^= h >> 32;
    return h;
}

inline fn xxh3_rrmxmx(h_: u64, len: u64) u64 {
    var h = h_;
    h ^= rotl(u64, h, 49) ^ rotl(u64, h, 24);
    h *%= PRIME_MX2;
    h ^= (h >> 35) +% len;
    h *%= PRIME_MX2;
    return h ^ (h >> 28);
}

inline fn hashLongInternalLoop(impl: anytype, acc: *Accumulator, input: []const u8, secret: []const u8) void {
    assert(secret.len >= SECRET_SIZE_MIN);

    const nb_stripes_per_block = (secret.len - STRIPE_LEN) / SECRET_CONSUME_RATE;
    const block_len = STRIPE_LEN * nb_stripes_per_block;
    const nb_blocks = (input.len - 1) / block_len;

    for (0..nb_blocks) |n| {
        impl.accumulate(acc, input[n * block_len ..], secret, nb_stripes_per_block);
        impl.scramble(acc, secret[secret.len - STRIPE_LEN ..]);
    }

    assert(input.len > STRIPE_LEN);
    const nb_stripes = ((input.len - 1) - (block_len * nb_blocks)) / STRIPE_LEN;
    assert(nb_stripes <= secret.len / SECRET_CONSUME_RATE);
    impl.accumulate(acc, input[nb_blocks * block_len ..], secret, nb_stripes);

    const SECRET_LASTACC_START = 7;
    impl.accumulate512(acc, input[input.len - STRIPE_LEN ..], secret[secret.len - STRIPE_LEN - SECRET_LASTACC_START ..]);
}

inline fn mixAccumulators(acc: *[2]u64, secret: []const u8) u64 {
    return mul128_fold64(
        acc[0] ^ readIntLittle(u64, secret[0..]),
        acc[1] ^ readIntLittle(u64, secret[8..]),
    );
}

inline fn mergeAccumulators(acc: *Accumulator, secret: []const u8, start: u64) u64 {
    var r = start;
    for (0..4) |i| {
        r +%= mixAccumulators(acc.e[2 * i ..][0..2], secret[16 * i ..]);
    }
    return xxh3_avalanche(r);
}

pub const Accumulator = struct {
    e: [ACC_NB]u64 align(64),

    pub fn init() Accumulator {
        return .{ .e = .{
            PRIME32_3, PRIME64_1, PRIME64_2, PRIME64_3,
            PRIME64_4, PRIME32_2, PRIME64_5, PRIME32_1,
        } };
    }
};

pub const XXH3_64 = struct {
    pub const Options = struct {
        seed: u64 = 0,
        secret: []const u8 = &DEFAULT_SECRET,
    };

    pub fn hash(input: []const u8, options: Options) u64 {
        return switch (input.len) {
            else => hashLong(getImpl(), input, options.secret, options.seed),
            129...240 => len_129to240(input, options.secret, options.seed),
            17...128 => len_17to128(input, options.secret, options.seed),
            0...16 => len_0to16(input, options.secret, options.seed),
        };
    }

    // Short Keys

    inline fn len_1to3(input: []const u8, secret: []const u8, seed: u64) u64 {
        assert(1 <= input.len and input.len <= 3);
        const c1: u32 = input[0];
        const c2: u32 = input[input.len >> 1];
        const c3: u32 = input[input.len - 1];
        const combined: u32 = @intCast((c1 << 16) | (c2 << 24) | (c3 << 0) | (input.len << 8));
        const bitflip: u64 = @as(u64, readIntLittle(u32, secret) ^ readIntLittle(u32, secret[4..])) +% seed;
        const keyed: u64 = @as(u64, combined) ^ bitflip;
        return xxh64_avalanche(keyed);
    }

    inline fn len_4to8(input: []const u8, secret: []const u8, seed_: u64) u64 {
        assert(4 <= input.len and input.len <= 8);
        const seed_swapped: u64 = @byteSwap(@as(u32, @truncate(seed_)));
        const seed = seed_ ^ (seed_swapped << 32);
        const input1 = readIntLittle(u32, input[0..]);
        const input2 = readIntLittle(u32, input[input.len - 4 ..]);
        const bitflip = (readIntLittle(u64, secret[8..]) ^ readIntLittle(u64, secret[16..])) -% seed;
        const input64 = input2 +% (@as(u64, input1) << 32);
        const keyed = input64 ^ bitflip;
        return xxh3_rrmxmx(keyed, input.len);
    }

    inline fn len_9to16(input: []const u8, secret: []const u8, seed: u64) u64 {
        assert(9 <= input.len and input.len <= 16);
        const bitflip1 = (readIntLittle(u64, secret[24..]) ^ readIntLittle(u64, secret[32..])) +% seed;
        const bitflip2 = (readIntLittle(u64, secret[40..]) ^ readIntLittle(u64, secret[48..])) -% seed;
        const input_lo = readIntLittle(u64, input[0..]) ^ bitflip1;
        const input_hi = readIntLittle(u64, input[input.len - 8 ..]) ^ bitflip2;
        const acc = input.len +% @byteSwap(input_lo) +% input_hi +% mul128_fold64(input_lo, input_hi);
        return xxh3_avalanche(acc);
    }

    inline fn len_0to16(input: []const u8, secret: []const u8, seed: u64) u64 {
        return switch (input.len) {
            else => unreachable,
            9...16 => len_9to16(input, secret, seed),
            4...8 => len_4to8(input, secret, seed),
            1...3 => len_1to3(input, secret, seed),
            0 => xxh64_avalanche(seed ^ (readIntLittle(u64, secret[56..]) ^ readIntLittle(u64, secret[64..]))),
        };
    }

    inline fn mix16(input: []const u8, secret: []const u8, seed: u64) u64 {
        assert(input.len >= 16);
        const input_lo = readIntLittle(u64, input[0..]);
        const input_hi = readIntLittle(u64, input[8..]);
        return mul128_fold64(
            input_lo ^ (readIntLittle(u64, secret[0..]) +% seed),
            input_hi ^ (readIntLittle(u64, secret[8..]) -% seed),
        );
    }

    inline fn len_17to128(input: []const u8, secret: []const u8, seed: u64) u64 {
        assert(secret.len >= SECRET_SIZE_MIN);
        assert(16 < input.len and input.len <= 128);
        var acc: u64 = input.len *% PRIME64_1;
        if (input.len > 32) {
            if (input.len > 64) {
                if (input.len > 96) {
                    acc +%= mix16(input[48..], secret[96..], seed);
                    acc +%= mix16(input[input.len - 64 ..], secret[112..], seed);
                }
                acc +%= mix16(input[32..], secret[64..], seed);
                acc +%= mix16(input[input.len - 48 ..], secret[80..], seed);
            }
            acc +%= mix16(input[16..], secret[32..], seed);
            acc +%= mix16(input[input.len - 32 ..], secret[48..], seed);
        }
        acc +%= mix16(input[0..], secret[0..], seed);
        acc +%= mix16(input[input.len - 16 ..], secret[16..], seed);
        return xxh3_avalanche(acc);
    }

    const MIDSIZE_MAX = 240;

    inline fn len_129to240(input: []const u8, secret: []const u8, seed: u64) u64 {
        assert(secret.len >= SECRET_SIZE_MIN);
        assert(128 < input.len and input.len <= MIDSIZE_MAX);
        const MIDSIZE_STARTOFFSET = 3;
        const MIDSIZE_LASTOFFSET = 17;

        const nb_rounds = input.len / 16;
        assert(nb_rounds >= 8);

        var acc: u64 = input.len *% PRIME64_1;
        for (0..8) |i| {
            acc +%= mix16(input[16 * i ..], secret[16 * i ..], seed);
        }
        acc = xxh3_avalanche(acc);

        var acc_end: u64 = mix16(input[input.len - 16 ..], secret[SECRET_SIZE_MIN - MIDSIZE_LASTOFFSET ..], seed);
        for (8..nb_rounds) |i| {
            acc_end +%= mix16(input[16 * i ..], secret[16 * (i - 8) + MIDSIZE_STARTOFFSET ..], seed);
        }
        return xxh3_avalanche(acc +% acc_end);
    }

    // Long Keys

    fn hashLong(impl: anytype, input: []const u8, secret: []const u8, seed: u64) u64 {
        if (seed == 0) {
            return hashLongInternal(impl, input, secret);
        } else {
            // TODO: Need to use custom secret if requested. Does the initSecret change to
            // base off the custom? Right now we always use the default when generating.
            var custom_secret: [SECRET_DEFAULT_SIZE]u8 align(SEC_ALIGN) = undefined;
            impl.initSecret(&custom_secret, seed);
            return hashLongInternal(impl, input, &custom_secret);
        }
    }

    inline fn hashLongInternal(impl: anytype, input: []const u8, secret: []const u8) u64 {
        const SECRET_MERGEACCS_START = 11;

        var acc = Accumulator.init();
        assert(secret.len >= @sizeOf(@TypeOf(acc)) + SECRET_MERGEACCS_START);
        hashLongInternalLoop(impl, &acc, input, secret);
        return mergeAccumulators(&acc, secret[SECRET_MERGEACCS_START..], input.len *% PRIME64_1);
    }
};

// XXH3 scalar/generic implementation

const scalar = struct {
    inline fn accumulateRound(acc: *Accumulator, input: []const u8, secret: []const u8, lane: usize) void {
        assert(lane < ACC_NB);
        const val = readIntLittle(u64, input[lane * 8 ..]);
        const key = val ^ readIntLittle(u64, secret[lane * 8 ..]);
        acc.e[lane ^ 1] +%= val;
        acc.e[lane] = mul32to64_add64(key, key >> 32, acc.e[lane]);
    }

    inline fn accumulate512(acc: *Accumulator, input: []const u8, secret: []const u8) void {
        for (0..ACC_NB) |i| {
            accumulateRound(acc, input, secret, i);
        }
    }

    inline fn accumulate(acc: *Accumulator, input: []const u8, secret: []const u8, nb_stripes: usize) void {
        for (0..nb_stripes) |n| {
            const in = input[n * STRIPE_LEN ..];
            @prefetch(in.ptr, .{});
            accumulate512(acc, in, secret[n * SECRET_CONSUME_RATE ..]);
        }
    }

    inline fn scrambleRound(acc: *Accumulator, secret: []const u8, lane: usize) void {
        // TODO: assert acc is aligned
        assert(lane < ACC_NB);
        const key = readIntLittle(u64, secret[lane * 8 ..]);
        var a = acc.e[lane];
        a ^= (a >> 47);
        a ^= key;
        a *%= PRIME32_1;
        acc.e[lane] = a;
    }

    inline fn scramble(acc: *Accumulator, secret: []const u8) void {
        for (0..ACC_NB) |i| {
            scrambleRound(acc, secret, i);
        }
    }

    inline fn initSecret(custom_secret: []u8, seed: u64) void {
        assert(SECRET_DEFAULT_SIZE % 16 == 0);
        const nb_rounds = SECRET_DEFAULT_SIZE / 16;
        for (0..nb_rounds) |i| {
            const lo = readIntLittle(u64, DEFAULT_SECRET[16 * i ..]) +% seed;
            const hi = readIntLittle(u64, DEFAULT_SECRET[16 * i + 8 ..]) -% seed;
            std.mem.writeIntLittle(u64, custom_secret[16 * i ..][0..8], lo);
            std.mem.writeIntLittle(u64, custom_secret[16 * i + 8 ..][0..8], hi);
        }
    }
};

fn getImpl() type {
    return scalar;
}

test "xxh3_64" {
    const seed = 0;
    const to_hash = "1234";
    const result = 0xd8316e61d84f6ba4;
    try std.testing.expectEqual(XXH3_64.hash(to_hash, .{ .seed = seed }), result);
}

pub fn main() !void {
    const buf = "a" ** 1024;
    for (0..1024) |i| {
        const zig_r = XXH3_64.hash(buf[0..i], .{});
        std.debug.print("{:0>3}: {x}\n", .{ i, zig_r });
    }
}
