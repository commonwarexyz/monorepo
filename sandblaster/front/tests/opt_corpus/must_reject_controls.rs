//! Controls of the corpus's frozen must-reject variants (`must_reject.rs`):
//! for every variant, a correct candidate of the same shape — the variant
//! with its bug fixed, so the variant is a one- or two-token mutation of it
//! (except P15, whose variant has no correct form of its shape).
//!
//! `tests/opt_reject.rs` proposes each control and each variant as the
//! program's candidate. A variant's rejection counts as must-reject evidence
//! only when its control is admitted (`must_reject_status = "attributable"`
//! in `corpus.toml`); while the route rejects the control too, the rejection
//! says nothing about the bug and the program is `pending` the milestone
//! whose route admits the variant's shape. Today every variant is pending:
//! the only route is tier-0 conversion, and these shapes (closed forms,
//! local helpers, loops) are not convertible or not straight-line whether
//! they are right or wrong. The conversion pairs (`conv_pairs.rs`) are
//! today's evidence.
//!
//! Helpers are copies of the corpus's (or of the variant's) with the bug
//! fixed, under their own names, as the variants' are. Like
//! `must_reject.rs`, this file is not part of the corpus crate and is frozen
//! once recorded (gate G6).
#![allow(dead_code)]
use sandblaster::prelude::*;

/// P1: `64 − lz` (the variant: `65 − lz`).
pub fn bit_length(x: u64) -> u32 {
    64 - x.leading_zeros()
}

/// P2: the highest set bit, 0 for 0 (the variant: 1 for 0).
pub fn floor_pow2(x: u64) -> u64 {
    if x == 0 { 0 } else { 1u64.wrapping_shl(63u32.wrapping_sub(x.leading_zeros())) }
}

/// P3: popcount of `x >> 0` (the variant: `x >> 1`).
pub fn popcount_loop(x: u64) -> u32 {
    (x >> 0u32).count_ones()
}

/// P4: the search started at the top level (the variant: one level down).
pub fn find_block(n: u64, idx: u64) -> Option<crate::Block> {
    find_block_go_64(64, idx, n, 1u64 << 63u32, 0, 0, None)
}

#[requires(fuel <= 64)]
#[requires((start as Int) + (rest as Int) <= 18446744073709551615)]
#[requires((rank as Int) + (fuel as Int) <= 64)]
#[decreases(fuel)]
fn find_block_go_64(fuel: u32, idx: u64, rest: u64, width: u64, start: u64, rank: u32, found: Option<crate::Block>) -> Option<crate::Block> {
    if fuel == 0 {
        return found;
    }
    if rest < width {
        find_block_go_64(fuel - 1, idx, rest, width / 2, start, rank, found)
    } else {
        let found = if idx >= start && idx - start < width { Some(crate::Block { level: fuel - 1, start, rank }) } else { found };
        find_block_go_64(fuel - 1, idx, rest - width, width / 2, start + width, rank + 1, found)
    }
}

/// P5: the 10th-byte range check `h < 2` (the variant: `h < 3`).
pub fn leb128(xs: &[u8]) -> Option<(u64, &[u8])> {
    leb128_go_exact(10, xs, 0, 0)
}

#[requires(fuel <= 10 && shift == 70 - 7 * fuel)]
#[decreases(fuel)]
fn leb128_go_exact(fuel: u32, xs: &[u8], shift: u32, acc: u64) -> Option<(u64, &[u8])> {
    if fuel == 0 {
        return None;
    }
    let [h, t @ ..] = xs else {
        return None;
    };
    let h = *h;
    let value = acc | (((h & 0x7f) as u64).wrapping_shl(shift));
    if h < 0x80 {
        if (fuel != 1 || h < 2) && (shift == 0 || h != 0) { Some((value, t)) } else { None }
    } else {
        leb128_go_exact(fuel - 1, t, shift + 7, value)
    }
}

/// P5b: all four varints in the result (the variant drops the fourth).
pub fn header4(xs: &[u8]) -> Option<u64> {
    let (a, s0) = crate::leb128(xs)?;
    let (b, s1) = crate::leb128(s0)?;
    let (c, s2) = crate::leb128(s1)?;
    let (d, _) = crate::leb128(s2)?;
    Some(a ^ b ^ c ^ d)
}

/// P6: `(bitlen(x | 1) + 6) / 7` (the variant drops the `| 1`).
pub fn varint_len(x: u64) -> u32 {
    (64 - (x | 1).leading_zeros() + 6) / 7
}

/// P7: `a` folded first, then `mid`, then `b` (the variant: `b` first).
pub fn concat_fold(a: &[u64], mid: u64, b: &[u64]) -> Option<u64> {
    if a.len() + b.len() >= crate::CAP {
        return None;
    }
    Some(fold_mix_c(b, mix_c(fold_mix_c(a, 0), mid)))
}

fn mix_c(acc: u64, x: u64) -> u64 {
    (acc ^ x).wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(29)
}

#[decreases(xs.len())]
fn fold_mix_c(xs: &[u64], acc: u64) -> u64 {
    match xs {
        [] => acc,
        [h, t @ ..] => fold_mix_c(t, mix_c(acc, *h)),
    }
}

/// P8: entry `k` (the variant: `k + 1`).
pub fn prefix_query(xs: &[u32; 64], k: usize) -> u64 {
    if k < 64 { crate::prefix_query(xs, k) } else { crate::prefix_query(xs, k) }
}

/// P9 (control program): the initial minimum `u32::MAX` (the variant: `u32::MAX − 1`).
pub fn min_max(xs: &[u32]) -> (u32, u32) {
    let mut lo: u32 = 4294967295;
    let mut hi: u32 = 0;
    for i in 0..xs.len() {
        lo = lo.min(xs[i]);
        hi = hi.max(xs[i]);
    }
    (lo, hi)
}

/// P10: the sum started at 0 (the variant: at 1).
pub fn sum_small(xs: &[u32]) -> Option<u64> {
    if xs.len() > 65536 {
        return None;
    }
    let mut s: u64 = 0;
    for i in 0..xs.len() {
        s = s.wrapping_add(xs[i] as u64);
    }
    Some(s)
}

/// P11: `ctz` of 0 is 64 (the variant: 0).
pub fn trailing_zeros_loop(x: u64) -> u32 {
    if x == 0 { 64 } else { x.trailing_zeros() }
}

/// P12: the stop test `< 0x80` (the variant: `<= 0x80`).
pub fn first_small(xs: &[u8]) -> Option<u64> {
    first_small_go_lt(xs, 0)
}

#[decreases(xs.len())]
fn first_small_go_lt(xs: &[u8], i: u64) -> Option<u64> {
    match xs {
        [] => None,
        [h, t @ ..] => {
            if *h < 0x80 { Some(i) } else { first_small_go_lt(t, i.wrapping_add(1)) }
        }
    }
}

/// P13: bits at positions `> k`: `n >> k >> 1` (the variant: `n >> k`).
pub fn rank_above(n: u64, k: u32) -> u32 {
    if k >= 64 { 0 } else { (n >> k >> 1u32).count_ones() }
}

/// P14 (control program): `n(n − 1)/2` (the variant: `n(n + 1)/2`).
pub fn series(n: u32) -> u64 {
    let m = n as u64;
    m.wrapping_mul(m.wrapping_sub(1)) / 2
}

/// P15: the program's own recursion, leaf count checked. The variant (a loop
/// over the levels from `leaves[0]`) has no correct form of its shape: a
/// loop over levels cannot read the other leaves.
pub fn tree_root(height: u32, leaves: &[u64]) -> Option<u64> {
    if height > crate::p15_tree_dfs::MAX_TREE_HEIGHT {
        return None;
    }
    let (d, c) = dfs_go_c(height, leaves, 0)?;
    if c == leaves.len() { Some(d) } else { None }
}

#[requires(height <= crate::p15_tree_dfs::MAX_TREE_HEIGHT)]
#[decreases(height, max = 16)]
fn dfs_go_c(height: u32, leaves: &[u64], cursor: usize) -> Option<(u64, usize)> {
    if height == 0 {
        if cursor < leaves.len() { Some((leaves[cursor], cursor + 1)) } else { None }
    } else {
        let (l, c1) = dfs_go_c(height - 1, leaves, cursor)?;
        let (r, c2) = dfs_go_c(height - 1, leaves, c1)?;
        Some((crate::p15_tree_dfs::tree_node(l, r), c2))
    }
}

/// P16: the sibling side decided by bit `i` of the index: `indices[k] >> 0`
/// (the variant: `>> 1`).
pub fn batch_roots(leaves: &[u64; 8], indices: &[u64; 8], siblings: &[[u64; 20]; 8]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for k in 0..8usize {
        out[k] = crate::p16_batch_paths::path_root(leaves[k], indices[k] >> 0u32, &siblings[k]);
    }
    out
}

/// P17: the reduction polynomial 0x1002D (the variant: 0x1002B).
pub fn gf16_mul_block(c: u16, block: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..32usize {
        let v = (block[i] as u16) | ((block[i + 32] as u16) << 8u32);
        let p = gf16_mul_2d(v, c);
        out[i] = (p & 0xff) as u8;
        out[i + 32] = (p >> 8u32) as u8;
    }
    out
}

fn gf16_double_2d(a: u16) -> u16 {
    let x = (a as u32) << 1u32;
    let r = if x >= 0x1_0000 { (x - 0x1_0000) ^ 0x002D } else { x };
    r as u16
}

fn gf16_mul_2d(a: u16, b: u16) -> u16 {
    let mut acc: u16 = 0;
    let mut x: u16 = a;
    for i in 0..16u32 {
        if (b >> i) & 1 == 1 {
            acc = acc ^ x;
        }
        x = gf16_double_2d(x);
    }
    acc
}

/// P18: the top limb kept (the variant replaces it with the high half of
/// `a3·b3` only).
pub fn mul_carry(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let r = crate::p18_carry_chain::mul_carry(a, b);
    [r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]]
}

/// P20: the specialized product with the `a[2]` term (the variant drops it).
pub fn line_mul(a: &[u64; 3], c: u64) -> [u64; 3] {
    let p = crate::p20_sparse_mul::clmul_lo(a[0], c);
    let q = crate::p20_sparse_mul::clmul_lo(a[1], c);
    [a[0], p ^ a[1], q ^ a[2]]
}
