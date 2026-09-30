//! The corpus's conversion must-reject pairs (docs/optimizer-plan.md O1, G4;
//! design §20): for every program, a **control** — a correct candidate of
//! the shape today's admission route (tier 0: a straight-line residual,
//! `Env::check_residual_equal`) accepts — and a **mutant**, the control with
//! one token changed so that it is wrong (`corpus.toml` names the token and
//! a witness input on which the mutant differs from the program).
//!
//! The pair is the evidence: `tests/opt_reject.rs` proposes the control and
//! then the mutant as the program's candidate through `OptTestHooks`. When
//! the control is admitted and the mutant is rejected, the rejection is due
//! to the mutation alone (`conv_status = "attributable"`). A control is the
//! entry's own body where that body is straight-line, or the optimizer's
//! tier-0 residual written out (P3, P16, P17).
//!
//! Where the entry has no straight-line form (its body is stuck on a `match`
//! of a neutral value, so the route can admit no candidate at all), the
//! control is the entry's body verbatim; the route rejects it exactly like
//! the mutant, and the pair is `pending` until a route admits the control
//! (plan O4: residual `If`/`Match`, `Link::Lemma`). The test asserts which
//! case holds, so a milestone that starts admitting a control has to record
//! it here deliberately.
//!
//! Like `must_reject.rs`, this file is not part of the corpus crate and is
//! frozen once recorded (gate G6). Each function has exactly the signature of
//! its program's entry point.
#![allow(dead_code)]
use sandblaster::prelude::*;

// ---- P1: fuel 64 -> 63 (wrong for x >= 2^63)
pub fn bit_length(x: u64) -> u32 {
    crate::bit_length_go(64, x, 0)
}

pub fn bit_length_mut(x: u64) -> u32 {
    crate::bit_length_go(63, x, 0)
}

// ---- P2: fuel 64 -> 63 (0 for x = 1)
pub fn floor_pow2(x: u64) -> u64 {
    crate::floor_pow2_go(64, x, 1u64 << 63u32)
}

pub fn floor_pow2_mut(x: u64) -> u64 {
    crate::floor_pow2_go(63, x, 1u64 << 63u32)
}

// ---- P3: the loop unrolled (the tier-0 residual); the mutant reads bit 2 twice, never bit 1
pub fn popcount_loop(x: u64) -> u32 {
    let c: u32 = 0;
    let c = c.wrapping_add(((x >> 0u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 1u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 2u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 3u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 4u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 5u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 6u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 7u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 8u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 9u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 10u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 11u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 12u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 13u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 14u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 15u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 16u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 17u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 18u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 19u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 20u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 21u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 22u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 23u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 24u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 25u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 26u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 27u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 28u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 29u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 30u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 31u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 32u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 33u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 34u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 35u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 36u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 37u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 38u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 39u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 40u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 41u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 42u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 43u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 44u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 45u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 46u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 47u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 48u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 49u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 50u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 51u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 52u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 53u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 54u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 55u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 56u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 57u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 58u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 59u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 60u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 61u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 62u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 63u32) & 1) as u32);
    c
}

pub fn popcount_loop_mut(x: u64) -> u32 {
    let c: u32 = 0;
    let c = c.wrapping_add(((x >> 0u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 2u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 2u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 3u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 4u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 5u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 6u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 7u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 8u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 9u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 10u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 11u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 12u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 13u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 14u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 15u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 16u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 17u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 18u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 19u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 20u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 21u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 22u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 23u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 24u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 25u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 26u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 27u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 28u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 29u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 30u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 31u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 32u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 33u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 34u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 35u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 36u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 37u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 38u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 39u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 40u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 41u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 42u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 43u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 44u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 45u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 46u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 47u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 48u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 49u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 50u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 51u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 52u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 53u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 54u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 55u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 56u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 57u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 58u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 59u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 60u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 61u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 62u32) & 1) as u32);
    let c = c.wrapping_add(((x >> 63u32) & 1) as u32);
    c
}

// ---- P4: the first width 2^63 -> 2^62 (every level one too high)
pub fn find_block(n: u64, idx: u64) -> Option<crate::Block> {
    crate::find_block_go(64, idx, n, 1u64 << 63u32, 0, 0, None)
}

pub fn find_block_mut(n: u64, idx: u64) -> Option<crate::Block> {
    crate::find_block_go(64, idx, n, 1u64 << 62u32, 0, 0, None)
}

// ---- P5: the accumulator starts at 1
pub fn leb128(xs: &[u8]) -> Option<(u64, &[u8])> {
    crate::leb128_go(10, xs, 0, 0)
}

pub fn leb128_mut(xs: &[u8]) -> Option<(u64, &[u8])> {
    crate::leb128_go(10, xs, 0, 1)
}

// ---- P5b (no straight-line form: `?` matches on a neutral): `c` for `d` in the result
pub fn header4(xs: &[u8]) -> Option<u64> {
    let (a, s0) = crate::leb128(xs)?;
    let (b, s1) = crate::leb128(s0)?;
    let (c, s2) = crate::leb128(s1)?;
    let (d, _) = crate::leb128(s2)?;
    Some(a ^ b ^ c ^ d)
}

pub fn header4_mut(xs: &[u8]) -> Option<u64> {
    let (a, s0) = crate::leb128(xs)?;
    let (b, s1) = crate::leb128(s0)?;
    let (c, s2) = crate::leb128(s1)?;
    let (d, _) = crate::leb128(s2)?;
    Some(a ^ b ^ c ^ c)
}

// ---- P6: the count starts at 1
pub fn varint_len(x: u64) -> u32 {
    crate::varint_len_go(x, 0)
}

pub fn varint_len_mut(x: u64) -> u32 {
    crate::varint_len_go(x, 1)
}

// ---- P7 (no straight-line form: the capacity test): the fold seeded with 1
pub fn concat_fold(a: &[u64], mid: u64, b: &[u64]) -> Option<u64> {
    let na = a.len();
    let nb = b.len();
    if na + nb >= crate::CAP {
        return None;
    }
    let mut buf = [0u64; crate::CAP];
    buf[0..na].copy_from_slice(a);
    buf[na] = mid;
    buf[na + 1..na + 1 + nb].copy_from_slice(b);
    Some(crate::fold_mix(&buf[0..na + 1 + nb], 0))
}

pub fn concat_fold_mut(a: &[u64], mid: u64, b: &[u64]) -> Option<u64> {
    let na = a.len();
    let nb = b.len();
    if na + nb >= crate::CAP {
        return None;
    }
    let mut buf = [0u64; crate::CAP];
    buf[0..na].copy_from_slice(a);
    buf[na] = mid;
    buf[na + 1..na + 1 + nb].copy_from_slice(b);
    Some(crate::fold_mix(&buf[0..na + 1 + nb], 1))
}

// ---- P8 (no straight-line form: `k <= 64` on a neutral `k`): 1 for an out-of-range `k`
pub fn prefix_query(xs: &[u32; 64], k: usize) -> u64 {
    let mut ps = [0u64; 65];
    for i in 0..64usize {
        ps[i + 1] = ps[i].wrapping_add(xs[i] as u64);
    }
    if k <= 64 { ps[k] } else { 0 }
}

pub fn prefix_query_mut(xs: &[u32; 64], k: usize) -> u64 {
    let mut ps = [0u64; 65];
    for i in 0..64usize {
        ps[i + 1] = ps[i].wrapping_add(xs[i] as u64);
    }
    if k <= 64 { ps[k] } else { 1 }
}

// ---- P9: the initial minimum u32::MAX - 1
pub fn min_max(xs: &[u32]) -> (u32, u32) {
    crate::min_max_go(xs, 4294967295, 0)
}

pub fn min_max_mut(xs: &[u32]) -> (u32, u32) {
    crate::min_max_go(xs, 4294967294, 0)
}

// ---- P10 (no straight-line form: the length test): the sum starts at 1
pub fn sum_small(xs: &[u32]) -> Option<u64> {
    if xs.len() > 65536 {
        return None;
    }
    crate::sum_checked_go(xs, 0)
}

pub fn sum_small_mut(xs: &[u32]) -> Option<u64> {
    if xs.len() > 65536 {
        return None;
    }
    crate::sum_checked_go(xs, 1)
}

// ---- P11: fuel 64 -> 63 (63 for 0)
pub fn trailing_zeros_loop(x: u64) -> u32 {
    crate::tz_go(64, x, 0)
}

pub fn trailing_zeros_loop_mut(x: u64) -> u32 {
    crate::tz_go(63, x, 0)
}

// ---- P12: the index starts at 1
pub fn first_small(xs: &[u8]) -> Option<u64> {
    crate::first_small_go(xs, 0)
}

pub fn first_small_mut(xs: &[u8]) -> Option<u64> {
    crate::first_small_go(xs, 1)
}

// ---- P13 (no straight-line form: the loop's test on a neutral `k`): `>=` for `>`
pub fn rank_above(n: u64, k: u32) -> u32 {
    let mut c: u32 = 0;
    for i in 0..64u32 {
        if i > k && (n >> i) & 1 == 1 {
            c = c.wrapping_add(1);
        }
    }
    c
}

pub fn rank_above_mut(n: u64, k: u32) -> u32 {
    let mut c: u32 = 0;
    for i in 0..64u32 {
        if i >= k && (n >> i) & 1 == 1 {
            c = c.wrapping_add(1);
        }
    }
    c
}

// ---- P14 (no straight-line form: the loop over a neutral bound): the sum starts at 1
pub fn series(n: u32) -> u64 {
    let mut s: u64 = 0;
    for i in 0..n {
        s = s.wrapping_add(i as u64);
    }
    s
}

pub fn series_mut(n: u32) -> u64 {
    let mut s: u64 = 1;
    for i in 0..n {
        s = s.wrapping_add(i as u64);
    }
    s
}

// ---- P15 (no straight-line form: the height test; `dfs_go` is private to its module, so
// the pair carries a copy): the cursor starts at 1
pub fn tree_root(height: u32, leaves: &[u64]) -> Option<u64> {
    if height > crate::p15_tree_dfs::MAX_TREE_HEIGHT {
        return None;
    }
    let (d, c) = dfs_go(height, leaves, 0)?;
    if c == leaves.len() { Some(d) } else { None }
}

pub fn tree_root_mut(height: u32, leaves: &[u64]) -> Option<u64> {
    if height > crate::p15_tree_dfs::MAX_TREE_HEIGHT {
        return None;
    }
    let (d, c) = dfs_go(height, leaves, 1)?;
    if c == leaves.len() { Some(d) } else { None }
}

#[requires(height <= crate::p15_tree_dfs::MAX_TREE_HEIGHT)]
#[decreases(height, max = 16)]
fn dfs_go(height: u32, leaves: &[u64], cursor: usize) -> Option<(u64, usize)> {
    if height == 0 {
        if cursor < leaves.len() { Some((leaves[cursor], cursor + 1)) } else { None }
    } else {
        let (l, c1) = dfs_go(height - 1, leaves, cursor)?;
        let (r, c2) = dfs_go(height - 1, leaves, c1)?;
        Some((crate::p15_tree_dfs::tree_node(l, r), c2))
    }
}

// ---- P16: the loop unrolled (the tier-0 residual); the mutant's last path starts from leaf 6
pub fn batch_roots(leaves: &[u64; 8], indices: &[u64; 8], siblings: &[[u64; 20]; 8]) -> [u64; 8] {
    [
        crate::p16_batch_paths::path_root(leaves[0], indices[0], &siblings[0]),
        crate::p16_batch_paths::path_root(leaves[1], indices[1], &siblings[1]),
        crate::p16_batch_paths::path_root(leaves[2], indices[2], &siblings[2]),
        crate::p16_batch_paths::path_root(leaves[3], indices[3], &siblings[3]),
        crate::p16_batch_paths::path_root(leaves[4], indices[4], &siblings[4]),
        crate::p16_batch_paths::path_root(leaves[5], indices[5], &siblings[5]),
        crate::p16_batch_paths::path_root(leaves[6], indices[6], &siblings[6]),
        crate::p16_batch_paths::path_root(leaves[7], indices[7], &siblings[7]),
    ]
}

pub fn batch_roots_mut(leaves: &[u64; 8], indices: &[u64; 8], siblings: &[[u64; 20]; 8]) -> [u64; 8] {
    [
        crate::p16_batch_paths::path_root(leaves[0], indices[0], &siblings[0]),
        crate::p16_batch_paths::path_root(leaves[1], indices[1], &siblings[1]),
        crate::p16_batch_paths::path_root(leaves[2], indices[2], &siblings[2]),
        crate::p16_batch_paths::path_root(leaves[3], indices[3], &siblings[3]),
        crate::p16_batch_paths::path_root(leaves[4], indices[4], &siblings[4]),
        crate::p16_batch_paths::path_root(leaves[5], indices[5], &siblings[5]),
        crate::p16_batch_paths::path_root(leaves[6], indices[6], &siblings[6]),
        crate::p16_batch_paths::path_root(leaves[6], indices[7], &siblings[7]),
    ]
}

// ---- P17: the loop unrolled (the tier-0 residual); the mutant's last element reads its high
// byte from byte 62, not 63
pub fn gf16_mul_block(c: u16, block: &[u8; 64]) -> [u8; 64] {
    let p0 = crate::p17_gf16_mul::gf16_mul((block[0] as u16) | ((block[32] as u16) << 8u32), c);
    let p1 = crate::p17_gf16_mul::gf16_mul((block[1] as u16) | ((block[33] as u16) << 8u32), c);
    let p2 = crate::p17_gf16_mul::gf16_mul((block[2] as u16) | ((block[34] as u16) << 8u32), c);
    let p3 = crate::p17_gf16_mul::gf16_mul((block[3] as u16) | ((block[35] as u16) << 8u32), c);
    let p4 = crate::p17_gf16_mul::gf16_mul((block[4] as u16) | ((block[36] as u16) << 8u32), c);
    let p5 = crate::p17_gf16_mul::gf16_mul((block[5] as u16) | ((block[37] as u16) << 8u32), c);
    let p6 = crate::p17_gf16_mul::gf16_mul((block[6] as u16) | ((block[38] as u16) << 8u32), c);
    let p7 = crate::p17_gf16_mul::gf16_mul((block[7] as u16) | ((block[39] as u16) << 8u32), c);
    let p8 = crate::p17_gf16_mul::gf16_mul((block[8] as u16) | ((block[40] as u16) << 8u32), c);
    let p9 = crate::p17_gf16_mul::gf16_mul((block[9] as u16) | ((block[41] as u16) << 8u32), c);
    let p10 = crate::p17_gf16_mul::gf16_mul((block[10] as u16) | ((block[42] as u16) << 8u32), c);
    let p11 = crate::p17_gf16_mul::gf16_mul((block[11] as u16) | ((block[43] as u16) << 8u32), c);
    let p12 = crate::p17_gf16_mul::gf16_mul((block[12] as u16) | ((block[44] as u16) << 8u32), c);
    let p13 = crate::p17_gf16_mul::gf16_mul((block[13] as u16) | ((block[45] as u16) << 8u32), c);
    let p14 = crate::p17_gf16_mul::gf16_mul((block[14] as u16) | ((block[46] as u16) << 8u32), c);
    let p15 = crate::p17_gf16_mul::gf16_mul((block[15] as u16) | ((block[47] as u16) << 8u32), c);
    let p16 = crate::p17_gf16_mul::gf16_mul((block[16] as u16) | ((block[48] as u16) << 8u32), c);
    let p17 = crate::p17_gf16_mul::gf16_mul((block[17] as u16) | ((block[49] as u16) << 8u32), c);
    let p18 = crate::p17_gf16_mul::gf16_mul((block[18] as u16) | ((block[50] as u16) << 8u32), c);
    let p19 = crate::p17_gf16_mul::gf16_mul((block[19] as u16) | ((block[51] as u16) << 8u32), c);
    let p20 = crate::p17_gf16_mul::gf16_mul((block[20] as u16) | ((block[52] as u16) << 8u32), c);
    let p21 = crate::p17_gf16_mul::gf16_mul((block[21] as u16) | ((block[53] as u16) << 8u32), c);
    let p22 = crate::p17_gf16_mul::gf16_mul((block[22] as u16) | ((block[54] as u16) << 8u32), c);
    let p23 = crate::p17_gf16_mul::gf16_mul((block[23] as u16) | ((block[55] as u16) << 8u32), c);
    let p24 = crate::p17_gf16_mul::gf16_mul((block[24] as u16) | ((block[56] as u16) << 8u32), c);
    let p25 = crate::p17_gf16_mul::gf16_mul((block[25] as u16) | ((block[57] as u16) << 8u32), c);
    let p26 = crate::p17_gf16_mul::gf16_mul((block[26] as u16) | ((block[58] as u16) << 8u32), c);
    let p27 = crate::p17_gf16_mul::gf16_mul((block[27] as u16) | ((block[59] as u16) << 8u32), c);
    let p28 = crate::p17_gf16_mul::gf16_mul((block[28] as u16) | ((block[60] as u16) << 8u32), c);
    let p29 = crate::p17_gf16_mul::gf16_mul((block[29] as u16) | ((block[61] as u16) << 8u32), c);
    let p30 = crate::p17_gf16_mul::gf16_mul((block[30] as u16) | ((block[62] as u16) << 8u32), c);
    let p31 = crate::p17_gf16_mul::gf16_mul((block[31] as u16) | ((block[63] as u16) << 8u32), c);
    [
        (p0 & 0xff) as u8,
        (p1 & 0xff) as u8,
        (p2 & 0xff) as u8,
        (p3 & 0xff) as u8,
        (p4 & 0xff) as u8,
        (p5 & 0xff) as u8,
        (p6 & 0xff) as u8,
        (p7 & 0xff) as u8,
        (p8 & 0xff) as u8,
        (p9 & 0xff) as u8,
        (p10 & 0xff) as u8,
        (p11 & 0xff) as u8,
        (p12 & 0xff) as u8,
        (p13 & 0xff) as u8,
        (p14 & 0xff) as u8,
        (p15 & 0xff) as u8,
        (p16 & 0xff) as u8,
        (p17 & 0xff) as u8,
        (p18 & 0xff) as u8,
        (p19 & 0xff) as u8,
        (p20 & 0xff) as u8,
        (p21 & 0xff) as u8,
        (p22 & 0xff) as u8,
        (p23 & 0xff) as u8,
        (p24 & 0xff) as u8,
        (p25 & 0xff) as u8,
        (p26 & 0xff) as u8,
        (p27 & 0xff) as u8,
        (p28 & 0xff) as u8,
        (p29 & 0xff) as u8,
        (p30 & 0xff) as u8,
        (p31 & 0xff) as u8,
        (p0 >> 8u32) as u8,
        (p1 >> 8u32) as u8,
        (p2 >> 8u32) as u8,
        (p3 >> 8u32) as u8,
        (p4 >> 8u32) as u8,
        (p5 >> 8u32) as u8,
        (p6 >> 8u32) as u8,
        (p7 >> 8u32) as u8,
        (p8 >> 8u32) as u8,
        (p9 >> 8u32) as u8,
        (p10 >> 8u32) as u8,
        (p11 >> 8u32) as u8,
        (p12 >> 8u32) as u8,
        (p13 >> 8u32) as u8,
        (p14 >> 8u32) as u8,
        (p15 >> 8u32) as u8,
        (p16 >> 8u32) as u8,
        (p17 >> 8u32) as u8,
        (p18 >> 8u32) as u8,
        (p19 >> 8u32) as u8,
        (p20 >> 8u32) as u8,
        (p21 >> 8u32) as u8,
        (p22 >> 8u32) as u8,
        (p23 >> 8u32) as u8,
        (p24 >> 8u32) as u8,
        (p25 >> 8u32) as u8,
        (p26 >> 8u32) as u8,
        (p27 >> 8u32) as u8,
        (p28 >> 8u32) as u8,
        (p29 >> 8u32) as u8,
        (p30 >> 8u32) as u8,
        (p31 >> 8u32) as u8,
    ]
}

pub fn gf16_mul_block_mut(c: u16, block: &[u8; 64]) -> [u8; 64] {
    let p0 = crate::p17_gf16_mul::gf16_mul((block[0] as u16) | ((block[32] as u16) << 8u32), c);
    let p1 = crate::p17_gf16_mul::gf16_mul((block[1] as u16) | ((block[33] as u16) << 8u32), c);
    let p2 = crate::p17_gf16_mul::gf16_mul((block[2] as u16) | ((block[34] as u16) << 8u32), c);
    let p3 = crate::p17_gf16_mul::gf16_mul((block[3] as u16) | ((block[35] as u16) << 8u32), c);
    let p4 = crate::p17_gf16_mul::gf16_mul((block[4] as u16) | ((block[36] as u16) << 8u32), c);
    let p5 = crate::p17_gf16_mul::gf16_mul((block[5] as u16) | ((block[37] as u16) << 8u32), c);
    let p6 = crate::p17_gf16_mul::gf16_mul((block[6] as u16) | ((block[38] as u16) << 8u32), c);
    let p7 = crate::p17_gf16_mul::gf16_mul((block[7] as u16) | ((block[39] as u16) << 8u32), c);
    let p8 = crate::p17_gf16_mul::gf16_mul((block[8] as u16) | ((block[40] as u16) << 8u32), c);
    let p9 = crate::p17_gf16_mul::gf16_mul((block[9] as u16) | ((block[41] as u16) << 8u32), c);
    let p10 = crate::p17_gf16_mul::gf16_mul((block[10] as u16) | ((block[42] as u16) << 8u32), c);
    let p11 = crate::p17_gf16_mul::gf16_mul((block[11] as u16) | ((block[43] as u16) << 8u32), c);
    let p12 = crate::p17_gf16_mul::gf16_mul((block[12] as u16) | ((block[44] as u16) << 8u32), c);
    let p13 = crate::p17_gf16_mul::gf16_mul((block[13] as u16) | ((block[45] as u16) << 8u32), c);
    let p14 = crate::p17_gf16_mul::gf16_mul((block[14] as u16) | ((block[46] as u16) << 8u32), c);
    let p15 = crate::p17_gf16_mul::gf16_mul((block[15] as u16) | ((block[47] as u16) << 8u32), c);
    let p16 = crate::p17_gf16_mul::gf16_mul((block[16] as u16) | ((block[48] as u16) << 8u32), c);
    let p17 = crate::p17_gf16_mul::gf16_mul((block[17] as u16) | ((block[49] as u16) << 8u32), c);
    let p18 = crate::p17_gf16_mul::gf16_mul((block[18] as u16) | ((block[50] as u16) << 8u32), c);
    let p19 = crate::p17_gf16_mul::gf16_mul((block[19] as u16) | ((block[51] as u16) << 8u32), c);
    let p20 = crate::p17_gf16_mul::gf16_mul((block[20] as u16) | ((block[52] as u16) << 8u32), c);
    let p21 = crate::p17_gf16_mul::gf16_mul((block[21] as u16) | ((block[53] as u16) << 8u32), c);
    let p22 = crate::p17_gf16_mul::gf16_mul((block[22] as u16) | ((block[54] as u16) << 8u32), c);
    let p23 = crate::p17_gf16_mul::gf16_mul((block[23] as u16) | ((block[55] as u16) << 8u32), c);
    let p24 = crate::p17_gf16_mul::gf16_mul((block[24] as u16) | ((block[56] as u16) << 8u32), c);
    let p25 = crate::p17_gf16_mul::gf16_mul((block[25] as u16) | ((block[57] as u16) << 8u32), c);
    let p26 = crate::p17_gf16_mul::gf16_mul((block[26] as u16) | ((block[58] as u16) << 8u32), c);
    let p27 = crate::p17_gf16_mul::gf16_mul((block[27] as u16) | ((block[59] as u16) << 8u32), c);
    let p28 = crate::p17_gf16_mul::gf16_mul((block[28] as u16) | ((block[60] as u16) << 8u32), c);
    let p29 = crate::p17_gf16_mul::gf16_mul((block[29] as u16) | ((block[61] as u16) << 8u32), c);
    let p30 = crate::p17_gf16_mul::gf16_mul((block[30] as u16) | ((block[62] as u16) << 8u32), c);
    let p31 = crate::p17_gf16_mul::gf16_mul((block[31] as u16) | ((block[62] as u16) << 8u32), c);
    [
        (p0 & 0xff) as u8,
        (p1 & 0xff) as u8,
        (p2 & 0xff) as u8,
        (p3 & 0xff) as u8,
        (p4 & 0xff) as u8,
        (p5 & 0xff) as u8,
        (p6 & 0xff) as u8,
        (p7 & 0xff) as u8,
        (p8 & 0xff) as u8,
        (p9 & 0xff) as u8,
        (p10 & 0xff) as u8,
        (p11 & 0xff) as u8,
        (p12 & 0xff) as u8,
        (p13 & 0xff) as u8,
        (p14 & 0xff) as u8,
        (p15 & 0xff) as u8,
        (p16 & 0xff) as u8,
        (p17 & 0xff) as u8,
        (p18 & 0xff) as u8,
        (p19 & 0xff) as u8,
        (p20 & 0xff) as u8,
        (p21 & 0xff) as u8,
        (p22 & 0xff) as u8,
        (p23 & 0xff) as u8,
        (p24 & 0xff) as u8,
        (p25 & 0xff) as u8,
        (p26 & 0xff) as u8,
        (p27 & 0xff) as u8,
        (p28 & 0xff) as u8,
        (p29 & 0xff) as u8,
        (p30 & 0xff) as u8,
        (p31 & 0xff) as u8,
        (p0 >> 8u32) as u8,
        (p1 >> 8u32) as u8,
        (p2 >> 8u32) as u8,
        (p3 >> 8u32) as u8,
        (p4 >> 8u32) as u8,
        (p5 >> 8u32) as u8,
        (p6 >> 8u32) as u8,
        (p7 >> 8u32) as u8,
        (p8 >> 8u32) as u8,
        (p9 >> 8u32) as u8,
        (p10 >> 8u32) as u8,
        (p11 >> 8u32) as u8,
        (p12 >> 8u32) as u8,
        (p13 >> 8u32) as u8,
        (p14 >> 8u32) as u8,
        (p15 >> 8u32) as u8,
        (p16 >> 8u32) as u8,
        (p17 >> 8u32) as u8,
        (p18 >> 8u32) as u8,
        (p19 >> 8u32) as u8,
        (p20 >> 8u32) as u8,
        (p21 >> 8u32) as u8,
        (p22 >> 8u32) as u8,
        (p23 >> 8u32) as u8,
        (p24 >> 8u32) as u8,
        (p25 >> 8u32) as u8,
        (p26 >> 8u32) as u8,
        (p27 >> 8u32) as u8,
        (p28 >> 8u32) as u8,
        (p29 >> 8u32) as u8,
        (p30 >> 8u32) as u8,
        (p31 >> 8u32) as u8,
    ]
}

// ---- P18: the last limb of `b` masked from `b[2]`, not `b[3]`
pub fn mul_carry(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    crate::p18_carry_chain::mul_carry_limbs(
        &[a[0] & crate::p18_carry_chain::MASK28, a[1] & crate::p18_carry_chain::MASK28, a[2] & crate::p18_carry_chain::MASK28, a[3] & crate::p18_carry_chain::MASK28],
        &[b[0] & crate::p18_carry_chain::MASK28, b[1] & crate::p18_carry_chain::MASK28, b[2] & crate::p18_carry_chain::MASK28, b[3] & crate::p18_carry_chain::MASK28],
    )
}

pub fn mul_carry_mut(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    crate::p18_carry_chain::mul_carry_limbs(
        &[a[0] & crate::p18_carry_chain::MASK28, a[1] & crate::p18_carry_chain::MASK28, a[2] & crate::p18_carry_chain::MASK28, a[3] & crate::p18_carry_chain::MASK28],
        &[b[0] & crate::p18_carry_chain::MASK28, b[1] & crate::p18_carry_chain::MASK28, b[2] & crate::p18_carry_chain::MASK28, b[2] & crate::p18_carry_chain::MASK28],
    )
}

// ---- P20: the sparse operand (1, c, 1) for (1, c, 0)
pub fn line_mul(a: &[u64; 3], c: u64) -> [u64; 3] {
    crate::p20_sparse_mul::poly3_mul(a, &[1, c, 0])
}

pub fn line_mul_mut(a: &[u64; 3], c: u64) -> [u64; 3] {
    crate::p20_sparse_mul::poly3_mul(a, &[1, c, 1])
}
