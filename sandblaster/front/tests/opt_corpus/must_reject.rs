//! The corpus's must-reject variants (docs/optimizer-plan.md O1, design §15):
//! for every program, a plausible but wrong candidate of the kind an
//! untrusted summarizer could propose (an off-by-one closed form, a dropped
//! guard, swapped segments, a wrong constant). Each function has exactly the
//! signature of its program's entry point, and `corpus.toml` names a witness
//! input on which it differs from the program.
//!
//! This file is not part of the corpus crate. `tests/opt_reject.rs` mounts it
//! as module `must_reject` of a copy of the corpus, checks on the witness
//! (kernel evaluation) that each variant really is wrong, then proposes each
//! as its program's candidate through `OptTestHooks` and asserts that the
//! kernel rejects it and the proven fallback is emitted. Every later
//! milestone runs them through its own admission route.
#![allow(dead_code)]
use sandblaster::prelude::*;

/// P1: the closed form off by one (`65 − lz` for `64 − lz`).
pub fn bit_length(x: u64) -> u32 {
    65 - x.leading_zeros()
}

/// P2: the highest set bit, but 1 for 0.
pub fn floor_pow2(x: u64) -> u64 {
    if x == 0 { 1 } else { 1u64.wrapping_shl(63u32.wrapping_sub(x.leading_zeros())) }
}

/// P3: popcount of `x >> 1` (the loop's first step dropped).
pub fn popcount_loop(x: u64) -> u32 {
    (x >> 1u32).count_ones()
}

/// P4: the search started one level down (wrong for `n ≥ 2^63`).
pub fn find_block(n: u64, idx: u64) -> Option<crate::Block> {
    find_block_go_63(63, idx, n, 1u64 << 62u32, 0, 0, None)
}

#[requires(fuel <= 64)]
#[requires((start as Int) + (rest as Int) <= 18446744073709551615)]
#[requires((rank as Int) + (fuel as Int) <= 64)]
#[decreases(fuel)]
fn find_block_go_63(fuel: u32, idx: u64, rest: u64, width: u64, start: u64, rank: u32, found: Option<crate::Block>) -> Option<crate::Block> {
    if fuel == 0 {
        return found;
    }
    if rest < width {
        find_block_go_63(fuel - 1, idx, rest, width / 2, start, rank, found)
    } else {
        let found = if idx >= start && idx - start < width { Some(crate::Block { level: fuel - 1, start, rank }) } else { found };
        find_block_go_63(fuel - 1, idx, rest - width, width / 2, start + width, rank + 1, found)
    }
}

/// P5: the 10th-byte range check off by one (accepts 0x02).
pub fn leb128(xs: &[u8]) -> Option<(u64, &[u8])> {
    leb128_go_loose(10, xs, 0, 0)
}

#[requires(fuel <= 10 && shift == 70 - 7 * fuel)]
#[decreases(fuel)]
fn leb128_go_loose(fuel: u32, xs: &[u8], shift: u32, acc: u64) -> Option<(u64, &[u8])> {
    if fuel == 0 {
        return None;
    }
    let [h, t @ ..] = xs else {
        return None;
    };
    let h = *h;
    let value = acc | (((h & 0x7f) as u64).wrapping_shl(shift));
    if h < 0x80 {
        if (fuel != 1 || h < 3) && (shift == 0 || h != 0) { Some((value, t)) } else { None }
    } else {
        leb128_go_loose(fuel - 1, t, shift + 7, value)
    }
}

/// P5b: the fourth varint read but dropped from the result.
pub fn header4(xs: &[u8]) -> Option<u64> {
    let (a, s0) = crate::leb128(xs)?;
    let (b, s1) = crate::leb128(s0)?;
    let (c, s2) = crate::leb128(s1)?;
    let (_d, _) = crate::leb128(s2)?;
    Some(a ^ b ^ c)
}

/// P6: `(bitlen + 6) / 7` without the `| 1` (0 for 0).
pub fn varint_len(x: u64) -> u32 {
    (64 - x.leading_zeros() + 6) / 7
}

/// P7: the segments folded in the wrong order (`b` before `a`).
pub fn concat_fold(a: &[u64], mid: u64, b: &[u64]) -> Option<u64> {
    if a.len() + b.len() >= crate::CAP {
        return None;
    }
    Some(fold_mix_rm(a, crate_mix(fold_mix_rm(b, 0), mid)))
}

fn crate_mix(acc: u64, x: u64) -> u64 {
    (acc ^ x).wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(29)
}

#[decreases(xs.len())]
fn fold_mix_rm(xs: &[u64], acc: u64) -> u64 {
    match xs {
        [] => acc,
        [h, t @ ..] => fold_mix_rm(t, crate_mix(acc, *h)),
    }
}

/// P8: the query off by one (entry `k + 1`).
pub fn prefix_query(xs: &[u32; 64], k: usize) -> u64 {
    if k < 64 { crate::prefix_query(xs, k + 1) } else { crate::prefix_query(xs, k) }
}

/// P9 (control): the wrong initial minimum.
pub fn min_max(xs: &[u32]) -> (u32, u32) {
    let mut lo: u32 = 4294967294;
    let mut hi: u32 = 0;
    for i in 0..xs.len() {
        lo = lo.min(xs[i]);
        hi = hi.max(xs[i]);
    }
    (lo, hi)
}

/// P10: the sum started at 1.
pub fn sum_small(xs: &[u32]) -> Option<u64> {
    if xs.len() > 65536 {
        return None;
    }
    let mut s: u64 = 1;
    for i in 0..xs.len() {
        s = s.wrapping_add(xs[i] as u64);
    }
    Some(s)
}

/// P11: `ctz` of 0 taken as 0 (the fuel bound ignored).
pub fn trailing_zeros_loop(x: u64) -> u32 {
    if x == 0 { 0 } else { x.trailing_zeros() }
}

/// P12: the stop test off by one (`≤ 0x80`).
pub fn first_small(xs: &[u8]) -> Option<u64> {
    first_small_go_le(xs, 0)
}

#[decreases(xs.len())]
fn first_small_go_le(xs: &[u8], i: u64) -> Option<u64> {
    match xs {
        [] => None,
        [h, t @ ..] => {
            if *h <= 0x80 { Some(i) } else { first_small_go_le(t, i.wrapping_add(1)) }
        }
    }
}

/// P13: bits at positions `≥ k` instead of `> k`.
pub fn rank_above(n: u64, k: u32) -> u32 {
    if k >= 64 { 0 } else { (n >> k).count_ones() }
}

/// P14 (control): `n(n+1)/2` for `n(n−1)/2`.
pub fn series(n: u32) -> u64 {
    let m = n as u64;
    m.wrapping_mul(m + 1) / 2
}

/// P15: the leaf count never checked (the cursor's final value dropped).
pub fn tree_root(height: u32, leaves: &[u64]) -> Option<u64> {
    if height > 12 || leaves.is_empty() {
        return None;
    }
    let mut acc: u64 = leaves[0];
    for _level in 0..height {
        acc = crate::p15_tree_dfs::tree_node(acc, acc);
    }
    Some(acc)
}

/// P16: the sibling side decided by the wrong index bit (bit `i + 1`).
pub fn batch_roots(leaves: &[u64; 8], indices: &[u64; 8], siblings: &[[u64; 20]; 8]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for k in 0..8usize {
        out[k] = crate::p16_batch_paths::path_root(leaves[k], indices[k] >> 1u32, &siblings[k]);
    }
    out
}

/// P17: the wrong reduction polynomial (0x1002B).
pub fn gf16_mul_block(c: u16, block: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..32usize {
        let v = (block[i] as u16) | ((block[i + 32] as u16) << 8u32);
        let p = gf16_mul_2b(v, c);
        out[i] = (p & 0xff) as u8;
        out[i + 32] = (p >> 8u32) as u8;
    }
    out
}

fn gf16_double_2b(a: u16) -> u16 {
    let x = (a as u32) << 1u32;
    let r = if x >= 0x1_0000 { (x - 0x1_0000) ^ 0x002B } else { x };
    r as u16
}

fn gf16_mul_2b(a: u16, b: u16) -> u16 {
    let mut acc: u16 = 0;
    let mut x: u16 = a;
    for i in 0..16u32 {
        if (b >> i) & 1 == 1 {
            acc = acc ^ x;
        }
        x = gf16_double_2b(x);
    }
    acc
}

/// P18: the last carry dropped (the top limb is the high half of `a3·b3` only).
pub fn mul_carry(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let r = crate::p18_carry_chain::mul_carry(a, b);
    let p33 = (a[3] & crate::p18_carry_chain::MASK28) * (b[3] & crate::p18_carry_chain::MASK28);
    [r[0], r[1], r[2], r[3], r[4], r[5], r[6], p33 >> 28u32]
}

/// P20: the specialized product with the `a[2]` term dropped.
pub fn line_mul(a: &[u64; 3], c: u64) -> [u64; 3] {
    let p = crate::p20_sparse_mul::clmul_lo(a[0], c);
    let q = crate::p20_sparse_mul::clmul_lo(a[1], c);
    [a[0], p ^ a[1], q]
}
