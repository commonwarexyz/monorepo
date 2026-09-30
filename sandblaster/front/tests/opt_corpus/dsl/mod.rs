//! A general optimizer benchmark corpus (not QMDB): small, simple sandblaster
//! programs written the way a user would write them, each exhibiting one
//! pattern behind the QMDB u64-domain regression or another missed
//! optimization. Each has a closed-form / fused / unrolled "ideal" that a
//! compositional symbolic executor should emit (see ideal.rs in the harness).
#![forbid(unsafe_code)]

use sandblaster::prelude::*;

// ---------------------------------------------------------------- P1 bit length (shift-until-zero loop)
/// Number of significant bits of `x`: shift right until zero, with fuel.
#[requires(fuel <= 64 && n <= 64 - fuel)]
#[decreases(fuel)]
fn bit_length_go(fuel: u32, x: u64, n: u32) -> u32 {
    if fuel == 0 || x == 0 {
        n
    } else {
        bit_length_go(fuel - 1, x >> 1u32, n + 1)
    }
}

pub fn bit_length(x: u64) -> u32 {
    bit_length_go(64, x, 0)
}

// ---------------------------------------------------------------- P2 floor power of two (descending width search, early exit)
/// The largest power of two `<= x` (0 for 0), by trying `2^63, 2^62, ...`.
#[requires(fuel <= 64)]
#[decreases(fuel)]
fn floor_pow2_go(fuel: u32, x: u64, width: u64) -> u64 {
    if fuel == 0 {
        0
    } else if x >= width {
        width
    } else {
        floor_pow2_go(fuel - 1, x, width / 2)
    }
}

pub fn floor_pow2(x: u64) -> u64 {
    floor_pow2_go(64, x, 1u64 << 63u32)
}

// ---------------------------------------------------------------- P3 popcount (bit-sum loop)
/// Set bits of `x`, one bit per iteration.
pub fn popcount_loop(x: u64) -> u32 {
    let mut c: u32 = 0;
    for i in 0..64u32 {
        c = c.wrapping_add(((x >> i) & 1) as u32);
    }
    c
}

// ---------------------------------------------------------------- P4 binary-decomposition search (the MMR `shape` pattern, generic)
/// Where a leaf falls in the binary decomposition of `n` (largest block first):
/// Fenwick trees, MMR peaks, buddy allocators, binomial heaps.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Block {
    /// log2 of the block size.
    pub level: u32,
    /// First index covered by the block.
    pub start: u64,
    /// Blocks before this one.
    pub rank: u32,
}

#[requires(fuel <= 64)]
#[requires((start as Int) + (rest as Int) <= 18446744073709551615)]
#[requires((rank as Int) + (fuel as Int) <= 64)]
#[decreases(fuel)]
fn find_block_go(fuel: u32, idx: u64, rest: u64, width: u64, start: u64, rank: u32, found: Option<Block>) -> Option<Block> {
    if fuel == 0 {
        return found;
    }
    if rest < width {
        find_block_go(fuel - 1, idx, rest, width / 2, start, rank, found)
    } else {
        let found = if idx >= start && idx - start < width {
            Some(Block { level: fuel - 1, start, rank })
        } else {
            found
        };
        find_block_go(fuel - 1, idx, rest - width, width / 2, start + width, rank + 1, found)
    }
}

pub fn find_block(n: u64, idx: u64) -> Option<Block> {
    find_block_go(64, idx, n, 1u64 << 63u32, 0, 0, None)
}

// ---------------------------------------------------------------- P5 LEB128 u64 decode (fuel-bounded byte loop)
#[requires(fuel <= 10 && shift == 70 - 7 * fuel)]
#[decreases(fuel)]
fn leb128_go(fuel: u32, xs: &[u8], shift: u32, acc: u64) -> Option<(u64, &[u8])> {
    if fuel == 0 {
        return None;
    }
    let [h, t @ ..] = xs else {
        return None;
    };
    let h = *h;
    let value = acc | (((h & 0x7f) as u64) << shift);
    if h < 0x80 {
        if (fuel != 1 || h < 2) && (shift == 0 || h != 0) { Some((value, t)) } else { None }
    } else {
        leb128_go(fuel - 1, t, shift + 7, value)
    }
}

pub fn leb128(xs: &[u8]) -> Option<(u64, &[u8])> {
    leb128_go(10, xs, 0, 0)
}

/// Four varints in a row (a record header), each checked.
pub fn header4(xs: &[u8]) -> Option<u64> {
    let (a, s0) = leb128(xs)?;
    let (b, s1) = leb128(s0)?;
    let (c, s2) = leb128(s1)?;
    let (d, _) = leb128(s2)?;
    Some(a ^ b ^ c ^ d)
}

// ---------------------------------------------------------------- P6 varint length (divide-by-128 loop)
#[requires(n <= 9)]
#[decreases(9 - n)]
fn varint_len_go(x: u64, n: u32) -> u32 {
    if x < 128 || n == 9 {
        n + 1
    } else {
        varint_len_go(x >> 7u32, n + 1)
    }
}

pub fn varint_len(x: u64) -> u32 {
    varint_len_go(x, 0)
}

// ---------------------------------------------------------------- P7 concatenate into a zeroed buffer, then fold (the peak-buffer pattern)
fn mix(acc: u64, x: u64) -> u64 {
    (acc ^ x).wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(29)
}

#[decreases(xs.len())]
fn fold_mix(xs: &[u64], acc: u64) -> u64 {
    match xs {
        [] => acc,
        [h, t @ ..] => fold_mix(t, mix(acc, *h)),
    }
}

pub const CAP: usize = 256;

/// `fold(a ++ [mid] ++ b)` through a fixed stack buffer of `CAP` words.
pub fn concat_fold(a: &[u64], mid: u64, b: &[u64]) -> Option<u64> {
    let na = a.len();
    let nb = b.len();
    if na + nb >= CAP {
        return None;
    }
    let mut buf = [0u64; CAP];
    buf[0..na].copy_from_slice(a);
    buf[na] = mid;
    buf[na + 1..na + 1 + nb].copy_from_slice(b);
    Some(fold_mix(&buf[0..na + 1 + nb], 0))
}

// ---------------------------------------------------------------- P8 build a whole table, read one entry (prefix sums)
/// Prefix sums of 64 words, then entry `k` (`k <= 64`).
pub fn prefix_query(xs: &[u32; 64], k: usize) -> u64 {
    let mut ps = [0u64; 65];
    for i in 0..64usize {
        ps[i + 1] = ps[i].wrapping_add(xs[i] as u64);
    }
    if k <= 64 { ps[k] } else { 0 }
}

// ---------------------------------------------------------------- P9 min/max scan (tail recursion over a slice)
#[decreases(xs.len())]
fn min_max_go(xs: &[u32], lo: u32, hi: u32) -> (u32, u32) {
    match xs {
        [] => (lo, hi),
        [h, t @ ..] => min_max_go(t, lo.min(*h), hi.max(*h)),
    }
}

pub fn min_max(xs: &[u32]) -> (u32, u32) {
    min_max_go(xs, u32::MAX, 0)
}

// ---------------------------------------------------------------- P10 checked sum whose checks never fail (precondition makes them redundant)
#[requires(xs.len() <= 65536)]
#[decreases(xs.len())]
fn sum_checked_go(xs: &[u32], acc: u64) -> Option<u64> {
    match xs {
        [] => Some(acc),
        [h, t @ ..] => match acc.checked_add(*h as u64) {
            None => None,
            Some(a) => sum_checked_go(t, a),
        },
    }
}

/// Sum of at most 65536 words: `checked_add` can never fail.
pub fn sum_small(xs: &[u32]) -> Option<u64> {
    if xs.len() > 65536 {
        return None;
    }
    sum_checked_go(xs, 0)
}

// ---------------------------------------------------------------- P11 trailing zeros (shift-until-one loop)
#[requires(fuel <= 64 && n <= 64 - fuel)]
#[decreases(fuel)]
fn tz_go(fuel: u32, x: u64, n: u32) -> u32 {
    if fuel == 0 || x & 1 == 1 {
        n
    } else {
        tz_go(fuel - 1, x >> 1u32, n + 1)
    }
}

pub fn trailing_zeros_loop(x: u64) -> u32 {
    tz_go(64, x, 0)
}

// ---------------------------------------------------------------- P12 first byte with the top bit clear (search with early exit)
#[decreases(xs.len())]
fn first_small_go(xs: &[u8], i: u64) -> Option<u64> {
    match xs {
        [] => None,
        [h, t @ ..] => {
            if *h < 0x80 { Some(i) } else { first_small_go(t, i.wrapping_add(1)) }
        }
    }
}

/// Index of the first byte below 0x80 (a varint terminator), if any.
pub fn first_small(xs: &[u8]) -> Option<u64> {
    first_small_go(xs, 0)
}

// ---------------------------------------------------------------- P13 rank: set bits above position k (masked bit loop)
pub fn rank_above(n: u64, k: u32) -> u32 {
    let mut c: u32 = 0;
    for i in 0..64u32 {
        if i > k && (n >> i) & 1 == 1 {
            c = c.wrapping_add(1);
        }
    }
    c
}

// ---------------------------------------------------------------- P14 arithmetic series (control: LLVM already closes it)
pub fn series(n: u32) -> u64 {
    let mut s: u64 = 0;
    for i in 0..n {
        s = s.wrapping_add(i as u64);
    }
    s
}

// ---- additions (docs/optimizer-plan.md O1 and later) --------------------
// Everything above this line is frozen (gate G6: tools/gates/frozen.sha256
// hashes it). New programs are appended below as modules, one file each;
// once added, a program file is frozen as well.
pub mod p15_tree_dfs;
pub mod p16_batch_paths;
pub mod p17_gf16_mul;
pub mod p18_carry_chain;
pub mod p20_sparse_mul;
