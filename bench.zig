const std = @import("std");
const hash = std.hash;

const HashDefinition = struct {
    ty: type,
    output_size: usize, // remove and use resultType()
    verification: ?u32 = null,
    // seed_type, detect automatically from function definition
    seed: union(enum) {
        u32: u32,
        u64: u64,
        u8x16: [16]u8,
        none,
    } = .none,

    pub fn name(comptime def: HashDefinition) []const u8 {
        return @typeName(def.ty);
    }

    // fn resultType()
    // fn hashMaybeSeed()
    // fn initMaybeSeed()

    pub fn hasIterativeApi(comptime def: HashDefinition) bool {
        return @hasDecl(def.ty, "init") and @hasDecl(def.ty, "update");
    }

    pub fn hasCryptoApi(comptime def: HashDefinition) bool {
        return @hasDecl(def.ty, "finalInt");
    }

    pub fn hasAnytypeApi(comptime def: HashDefinition) bool {
        return @hasDecl(def.ty, "hash") and std.mem.indexOf(u8, @typeName(@TypeOf(def.ty.hash)), "anytype") != null;
    }
};

const defs = [_]HashDefinition{
    .{ .ty = hash.XxHash32, .seed = .{ .u32 = 0 }, .output_size = 4, .verification = 0xba88b743 },
    .{ .ty = hash.XxHash64, .seed = .{ .u64 = 0 }, .output_size = 8, .verification = 0x024b7cf4 },
    .{ .ty = hash.Wyhash, .seed = .{ .u64 = 0 }, .output_size = 8, .verification = 0xbd5e840c },
    .{ .ty = hash.Fnv1a_64, .output_size = 8 }, // no code
    .{ .ty = hash.Adler32, .output_size = 4 }, // no code
    .{ .ty = hash.crc.Crc32WithPoly(.IEEE), .output_size = 4 }, // no code
    .{ .ty = hash.crc.Crc32SmallWithPoly(.IEEE), .output_size = 4 }, // no code
    .{ .ty = hash.CityHash32, .output_size = 4, .verification = 0x5c28ad62 }, // fails
    .{ .ty = hash.CityHash64, .output_size = 8, .verification = 0x63fc6063 }, // fails
    .{ .ty = hash.Murmur2_32, .output_size = 4, .verification = 0x7fbd4396 }, // fails
    .{ .ty = hash.Murmur2_64, .output_size = 8, .verification = 0x1f0d3804 }, // fails
    //.{ .ty = hash.SipHash64(1, 3), .seed = .{ .u8x16 = [_]u8{0} ** 16 }, .output_size = 8, .verification = 0x29c010bf },
};

const options = struct {
    spawn_spin_cpu_thread: bool = false,
    validate_rtdsc: bool = false,

    run_verification: bool = true,

    run_small_key: bool = true,

    run_large_key: bool = true,
    large_key_block_size: usize = 8192,
};

pub fn main() !void {
    // Allocate memory up front.
    // 128MiB. No more memory allocations after the initial setup.

    const stdout = std.io.getStdOut().writer();
    const filter: ?[]const u8 = "wyhash";

    inline for (defs) |def| {
        if (filter == null or std.mem.indexOf(u8, def.name(), filter.?) != null) {
            try stdout.print("# {s}\n", .{def.name()});

            // Verification
            try stdout.print("{s}\n\n", .{if (verify(def)) "PASS" else "FAIL"});

            // Speed Test (small keys)
            try speedSmallKeys(def);
        }
    }
}

fn speedSmallKeys(comptime def: HashDefinition) !void {
    const no_of_trials = 1000;
    // Perform n trials and remove outliers

    // Fill with random seed data
    var buf: [64]u8 = undefined;
    @prefetch(buf[0..64], .{});

    // TODO: Restructure
    for (1..64) |key_size| {
        var sum: u64 = 0; // Use ResultType of hash
        var total_cycles: u64 = 0;
        var total_bytes: u64 = 0;
        for (0..no_of_trials) |_| {
            const s = Ticker.start();

            // Small keys we need some sort of amortization else call overhead inflates
            // cpb results.
            for (0..200) |_| {
                sum +%= blk: {
                    if (comptime def.seed == .none) {
                        break :blk def.ty.hash(buf[0..key_size]);
                    } else {
                        break :blk def.ty.hash(0, buf[0..key_size]);
                    }
                };
            }

            total_cycles += s.end();
            total_bytes += 200 * key_size;
        }
        std.mem.doNotOptimizeAway(sum);
        // TODO: Filter outliers here after ordering and take the average of all the trials.
        // We effectively have two sets of trials as a loop and the outer removes outliers?
        const cycles_per_byte = @as(f64, @floatFromInt(total_cycles)) / @as(f64, @floatFromInt(total_bytes));
        std.debug.print("KeySize: {}, CPB: {d:.2}\n", .{ key_size, cycles_per_byte });
    }
}

// smhasher verification test
fn verify(comptime def: HashDefinition) bool {
    var pass = true;

    const buf = blk: {
        var buf_i: [256]u8 = undefined;
        for (buf_i[0..], 0..) |*b, i| b.* = @intCast(i);
        break :blk buf_i;
    };
    // max output_size stored here
    var buf_all: [8 * 256]u8 = undefined;

    for (0..buf.len) |i| {
        const rd = blk: {
            if (comptime def.seed == .none) {
                break :blk def.ty.hash(buf[0..i]);
            } else {
                break :blk def.ty.hash(256 - @as(u32, @intCast(i)), buf[0..i]);
            }
        };

        // confirm iterative + direct hashing agree
        if (comptime def.hasIterativeApi()) {
            var hasher = blk: {
                if (comptime def.seed == .none) {
                    break :blk def.ty.init();
                } else {
                    break :blk def.ty.init(256 - @as(u32, @intCast(i)));
                }
            };
            for (buf[0..i]) |b| hasher.update(&[_]u8{b});
            const ri = hasher.final();
            const ri_2 = hasher.final();
            if (ri != ri_2) {
                std.debug.print("! final() call was not idempotent\n", .{});
                pass = false;
            }
            if (ri != rd) {
                std.debug.print("! hash() does not match iterative hasher\n", .{});
                pass = false;
            }
        }

        std.mem.writeIntLittle(@TypeOf(rd), buf_all[i * def.output_size ..][0..def.output_size], rd);
    }

    const verification = blk: {
        if (def.seed == .none) {
            break :blk def.ty.hash(buf_all[0 .. 256 * def.output_size]);
        } else {
            break :blk def.ty.hash(0, buf_all[0 .. 256 * def.output_size]);
        }
    };

    const v = @as(u32, @truncate(verification));
    if (def.verification != null and v != def.verification) {
        std.debug.print("! invalid verification code; found {x:08} want {x:08}\n", .{ v, def.verification.? });
        pass = false;
    }

    return pass;
}

// Some good notes here: https://github.com/marshallward/optiflop/blob/main/doc/microbench.rst
const Ticker = struct {
    start: u64,

    pub fn start() Ticker {
        return .{ .start = cpuid_rdtsc() };
    }

    pub fn end(self: Ticker) u64 {
        return rdtscp() - self.start;
    }

    fn cpuid_rdtsc() u64 {
        var lo: u64 = undefined;
        var hi: u64 = undefined;

        asm volatile (
            \\cpuid
            \\rdtsc
            : [lo] "={rax}" (lo),
              [hi] "={rdx}" (hi),
            :
            : "{rax}", "{rbx}", "{rcx}", "{rdx}"
        );

        return (hi << 32) | lo;
    }

    fn rdtscp() u64 {
        var lo: u64 = undefined;
        var hi: u64 = undefined;

        asm volatile (
            \\rdtscp
            \\movq %%rax, %[lo]
            \\movq %%rdx, %[hi]
            \\cpuid
            : [lo] "=m" (lo),
              [hi] "=m" (hi),
            :
            : "{rax}", "{rbx}", "{rcx}", "{rdx}"
        );

        return (hi << 32) | lo;
    }
};
