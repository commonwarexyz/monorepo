#![allow(unused_assignments)]
//! What a compositional symbolic executor should emit for each corpus program
//! (`corpus/dsl/mod.rs`): loop summaries (closed forms over clz/ctz/popcount),
//! full unrolling with early exits, build-fold fusion, query-driven slicing,
//! precondition-driven check elimination and word-at-a-time search. Each is
//! differentially tested against the generated code by the harness.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Block {
    pub level: u32,
    pub start: u64,
    pub rank: u32,
}

/// P1: loop idiom `x >>= 1; n += 1` until zero → `64 − clz(x)`.
#[inline(never)]
pub fn bit_length(x: u64) -> u32 { 64 - x.leading_zeros() }

/// P2: descending search with early exit → highest set bit.
#[inline(never)]
pub fn floor_pow2(x: u64) -> u64 { if x == 0 { 0 } else { 1u64 << (63 - x.leading_zeros()) } }

/// P3: bit-sum loop → popcount.
#[inline(never)]
pub fn popcount_loop(x: u64) -> u32 { x.count_ones() }

/// P4: binary-decomposition search → the block is decided by the highest bit where `n` and
/// `idx` differ; its rank is the popcount above it.
#[inline(never)]
pub fn find_block(n: u64, idx: u64) -> Option<Block> {
    if idx >= n {
        return None;
    }
    let h = 63 - (n ^ idx).leading_zeros();
    let above = u64::MAX.checked_shl(h + 1).unwrap_or(0); // bits > h
    Some(Block { level: h, start: n & above, rank: (n & above).count_ones() })
}

/// P5: LEB128 unrolled over the constant fuel, early exits.
#[inline(always)]
pub fn leb128_inl(xs: &[u8]) -> Option<(u64, &[u8])> {
    let mut t = xs;
    let mut v = 0u64;
    macro_rules! step {
        ($k:expr) => {{
            let [h, rest @ ..] = t else { return None };
            let h = *h;
            v |= ((h & 0x7f) as u64) << (7 * $k);
            if h < 0x80 {
                let ok = ($k != 9 || h < 2) && ($k == 0 || h != 0);
                return if ok { Some((v, rest)) } else { None };
            }
            t = rest;
        }};
    }
    step!(0); step!(1); step!(2); step!(3); step!(4);
    step!(5); step!(6); step!(7); step!(8); step!(9);
    None
}
#[inline(never)]
pub fn leb128(xs: &[u8]) -> Option<(u64, &[u8])> { leb128_inl(xs) }
#[inline(never)]
pub fn header4(xs: &[u8]) -> Option<u64> {
    let (a, s0) = leb128_inl(xs)?;
    let (b, s1) = leb128_inl(s0)?;
    let (c, s2) = leb128_inl(s1)?;
    let (d, _) = leb128_inl(s2)?;
    Some(a ^ b ^ c ^ d)
}

/// P6: divide-by-128 loop → `ceil(bit_length / 7)`, branch-free.
#[inline(never)]
pub fn varint_len(x: u64) -> u32 { (64 - (x | 1).leading_zeros() + 6) / 7 }

#[inline(always)]
fn mix(acc: u64, x: u64) -> u64 { (acc ^ x).wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(29) }

/// P7: build-fold fusion: fold the segments, no zeroed buffer, no copies.
#[inline(never)]
pub fn concat_fold(a: &[u64], mid: u64, b: &[u64]) -> Option<u64> {
    if a.len() + b.len() >= 256 {
        return None;
    }
    let mut acc = 0u64;
    for &x in a { acc = mix(acc, x); }
    acc = mix(acc, mid);
    for &x in b { acc = mix(acc, x); }
    Some(acc)
}

/// P8: query-driven slicing: only the prefix the query reads is computed.
#[inline(never)]
pub fn prefix_query(xs: &[u32; 64], k: usize) -> u64 {
    if k > 64 {
        return 0;
    }
    let mut s = 0u64;
    for &x in &xs[..k] { s += x as u64; }
    s
}

/// P9: the same scan as an indexed loop (vectorizable reduction).
#[inline(never)]
pub fn min_max(xs: &[u32]) -> (u32, u32) {
    let (mut lo, mut hi) = (u32::MAX, 0u32);
    for &x in xs {
        lo = lo.min(x);
        hi = hi.max(x);
    }
    (lo, hi)
}

/// P10: the precondition bounds the sum by 2^48, so `checked_add` never fails: plain sum.
#[inline(never)]
pub fn sum_small(xs: &[u32]) -> Option<u64> {
    if xs.len() > 65536 {
        return None;
    }
    let mut s = 0u64;
    for &x in xs { s += x as u64; }
    Some(s)
}

/// P11: shift-until-one loop → ctz.
#[inline(never)]
pub fn trailing_zeros_loop(x: u64) -> u32 { x.trailing_zeros() }

/// P12: search with early exit → 8 bytes per step (stop mask + ctz), byte tail.
#[inline(never)]
pub fn first_small(xs: &[u8]) -> Option<u64> {
    let (chunks, tail) = xs.as_chunks::<8>();
    for (k, c) in chunks.iter().enumerate() {
        let stop = !u64::from_le_bytes(*c) & 0x8080_8080_8080_8080;
        if stop != 0 {
            return Some((8 * k) as u64 + (stop.trailing_zeros() / 8) as u64);
        }
    }
    for (k, &b) in tail.iter().enumerate() {
        if b < 0x80 {
            return Some((8 * chunks.len() + k) as u64);
        }
    }
    None
}

/// P13: masked bit loop → shift + popcount.
#[inline(never)]
pub fn rank_above(n: u64, k: u32) -> u32 { if k >= 63 { 0 } else { (n >> (k + 1)).count_ones() } }

/// P14: arithmetic series → n(n−1)/2 (LLVM already does this).
#[inline(never)]
pub fn series(n: u32) -> u64 { let n = n as u64; n * n.saturating_sub(1) / 2 }

// ------------------------------------------------------------------------------------------
// P15-P20 (docs/optimizer-plan.md O1). Above: P1-P14 as recorded when the corpus was designed
// (research/optdesign/corpus/ideal).

/// P15/P16 node hashes, as in the DSL.
#[inline(always)]
pub fn tree_node(l: u64, r: u64) -> u64 {
    let x = (l ^ r.rotate_left(23)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let y = (x ^ (x >> 29)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    y ^ (y >> 32) ^ r
}
#[inline(always)]
pub fn path_node(l: u64, r: u64) -> u64 {
    let x = (l ^ r.rotate_left(17)).wrapping_mul(0xd6e8_feb8_6659_fd93);
    let y = (x ^ (x >> 32)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    y ^ (y >> 29) ^ l
}

/// P15: state decoupling. The cursor's effect of a subtree of height `h` is `+ 2^h`, so the
/// DFS's leaf-count checks collapse into one test and the two subtrees are independent: no
/// cursor, no per-leaf bounds checks, and the bottom levels computed as independent pairs
/// (interleaved chains).
#[inline(never)]
pub fn tree_root(height: u32, leaves: &[u64]) -> Option<u64> {
    if height > 12 || leaves.len() != 1usize << height {
        return None;
    }
    Some(root_pow2(height, leaves))
}

#[inline(always)]
fn root8(x: &[u64]) -> u64 {
    let (a, b, c, d) = (tree_node(x[0], x[1]), tree_node(x[2], x[3]), tree_node(x[4], x[5]), tree_node(x[6], x[7]));
    tree_node(tree_node(a, b), tree_node(c, d))
}

fn root_pow2(height: u32, x: &[u64]) -> u64 {
    match height {
        0 => x[0],
        1 => tree_node(x[0], x[1]),
        2 => tree_node(tree_node(x[0], x[1]), tree_node(x[2], x[3])),
        3 => root8(x),
        _ => {
            let (l, r) = x.split_at(x.len() / 2);
            tree_node(root_pow2(height - 1, l), root_pow2(height - 1, r))
        }
    }
}

/// P16: the K paths fused level by level (K independent chains in flight).
#[inline(never)]
pub fn batch_roots(leaves: &[u64; 8], indices: &[u64; 8], siblings: &[[u64; 20]; 8]) -> [u64; 8] {
    let mut acc = *leaves;
    for level in 0..20 {
        for k in 0..8 {
            let s = siblings[k][level];
            let right = (indices[k] >> level) & 1 == 1;
            let (l, r) = if right { (s, acc[k]) } else { (acc[k], s) };
            acc[k] = path_node(l, r);
        }
    }
    acc
}

#[inline(always)]
fn gf16_double(a: u16) -> u16 {
    let x = (a as u32) << 1;
    (if x >= 0x1_0000 { (x - 0x1_0000) ^ 0x2d } else { x }) as u16
}

/// The 4 nibble tables of `x ↦ c · x` (linear in the bits of x): images of the 16 basis
/// vectors, then every 4-bit combination by XOR.
#[inline(always)]
fn gf16_tables(c: u16) -> [[u16; 16]; 4] {
    let mut col = [0u16; 16];
    let mut x = c;
    for v in col.iter_mut() {
        *v = x;
        x = gf16_double(x);
    }
    let mut t = [[0u16; 16]; 4];
    for (q, tq) in t.iter_mut().enumerate() {
        for n in 1..16usize {
            tq[n] = tq[n & (n - 1)] ^ col[4 * q + n.trailing_zeros() as usize];
        }
    }
    t
}

/// P17: GF(2)-linear lowering of the multiplication by a constant: 4 nibble tables per call,
/// then TBL lookups (aarch64 NEON) or table lookups (portable).
#[inline(never)]
pub fn gf16_mul_block(c: u16, block: &[u8; 64]) -> [u8; 64] {
    let t = gf16_tables(c);
    #[cfg(target_arch = "aarch64")]
    {
        use core::arch::aarch64::*;
        let mut lo = [[0u8; 16]; 4];
        let mut hi = [[0u8; 16]; 4];
        for q in 0..4 {
            for n in 0..16 {
                lo[q][n] = t[q][n] as u8;
                hi[q][n] = (t[q][n] >> 8) as u8;
            }
        }
        let mut out = [0u8; 64];
        // SAFETY: NEON is part of the aarch64 baseline; every load/store is in bounds.
        unsafe {
            let m = vdupq_n_u8(15);
            let (l0, l1, l2, l3) = (vld1q_u8(lo[0].as_ptr()), vld1q_u8(lo[1].as_ptr()), vld1q_u8(lo[2].as_ptr()), vld1q_u8(lo[3].as_ptr()));
            let (h0, h1, h2, h3) = (vld1q_u8(hi[0].as_ptr()), vld1q_u8(hi[1].as_ptr()), vld1q_u8(hi[2].as_ptr()), vld1q_u8(hi[3].as_ptr()));
            for half in 0..2 {
                let a = vld1q_u8(block.as_ptr().add(16 * half));
                let b = vld1q_u8(block.as_ptr().add(32 + 16 * half));
                let (n0, n1, n2, n3) = (vandq_u8(a, m), vshrq_n_u8::<4>(a), vandq_u8(b, m), vshrq_n_u8::<4>(b));
                let rl = veorq_u8(veorq_u8(vqtbl1q_u8(l0, n0), vqtbl1q_u8(l1, n1)), veorq_u8(vqtbl1q_u8(l2, n2), vqtbl1q_u8(l3, n3)));
                let rh = veorq_u8(veorq_u8(vqtbl1q_u8(h0, n0), vqtbl1q_u8(h1, n1)), veorq_u8(vqtbl1q_u8(h2, n2), vqtbl1q_u8(h3, n3)));
                vst1q_u8(out.as_mut_ptr().add(16 * half), rl);
                vst1q_u8(out.as_mut_ptr().add(32 + 16 * half), rh);
            }
        }
        out
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let mut out = [0u8; 64];
        for i in 0..32 {
            let (a, b) = (block[i] as usize, block[i + 32] as usize);
            let p = t[0][a & 15] ^ t[1][a >> 4] ^ t[2][b & 15] ^ t[3][b >> 4];
            out[i] = p as u8;
            out[i + 32] = (p >> 8) as u8;
        }
        out
    }
}

/// P18: the same product and carry chain with wrapping (unchecked) operations: identical
/// code under `overflow-checks = false`; the E0 target under `overflow-checks = true`.
#[inline(never)]
pub fn mul_carry(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    const M: u64 = (1 << 28) - 1;
    mul_carry_limbs(&core::array::from_fn(|i| a[i] & M), &core::array::from_fn(|i| b[i] & M))
}

/// P18's kernel on limbs < 2^28 (the bounds are the caller's): the DSL's arithmetic with
/// every operation wrapping, what E0 prints for proven operations.
#[inline(never)]
pub fn mul_carry_limbs(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    const M: u64 = (1 << 28) - 1;
    let p = |i: usize, j: usize| a[i].wrapping_mul(b[j]);
    let (lo, hi) = (|x: u64| x & M, |x: u64| x >> 28);
    let s1 = lo(p(0, 1)).wrapping_add(lo(p(1, 0))).wrapping_add(hi(p(0, 0)));
    let s2 = lo(p(0, 2)).wrapping_add(lo(p(1, 1))).wrapping_add(lo(p(2, 0))).wrapping_add(hi(p(0, 1))).wrapping_add(hi(p(1, 0)));
    let s3 = lo(p(0, 3)).wrapping_add(lo(p(1, 2))).wrapping_add(lo(p(2, 1))).wrapping_add(lo(p(3, 0))).wrapping_add(hi(p(0, 2))).wrapping_add(hi(p(1, 1))).wrapping_add(hi(p(2, 0)));
    let s4 = lo(p(1, 3)).wrapping_add(lo(p(2, 2))).wrapping_add(lo(p(3, 1))).wrapping_add(hi(p(0, 3))).wrapping_add(hi(p(1, 2))).wrapping_add(hi(p(2, 1))).wrapping_add(hi(p(3, 0)));
    let s5 = lo(p(2, 3)).wrapping_add(lo(p(3, 2))).wrapping_add(hi(p(1, 3))).wrapping_add(hi(p(2, 2))).wrapping_add(hi(p(3, 1)));
    let s6 = lo(p(3, 3)).wrapping_add(hi(p(2, 3))).wrapping_add(hi(p(3, 2)));
    let t2 = s2.wrapping_add(s1 >> 28);
    let t3 = s3.wrapping_add(t2 >> 28);
    let t4 = s4.wrapping_add(t3 >> 28);
    let t5 = s5.wrapping_add(t4 >> 28);
    let t6 = s6.wrapping_add(t5 >> 28);
    let t7 = hi(p(3, 3)).wrapping_add(t6 >> 28);
    [lo(p(0, 0)), lo(s1), lo(t2), lo(t3), lo(t4), lo(t5), lo(t6), t7]
}

/// The exact 8-limb radix-2^28 product (an independent reference: schoolbook columns in
/// `u128`, then one carry pass).
pub fn mul_carry_exact(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    const M: u128 = (1 << 28) - 1;
    let mut out = [0u64; 8];
    // schoolbook columns in u128, then one carry pass
    let mut cols = [0u128; 8];
    for i in 0..4 {
        for j in 0..4 {
            cols[i + j] += ((a[i] as u128) & M) * ((b[j] as u128) & M);
        }
    }
    let mut carry = 0u128;
    for k in 0..8 {
        let t = cols[k] + carry;
        out[k] = (t & M) as u64;
        carry = t >> 28;
    }
    out
}

/// The DSL's carry-less product, as written and as the emitted code prints it, with no inlining
/// attribute (the ideal of P20 specializes the call sites, not the product: the same loop and
/// the same inlining freedom, so the ratio measures the specialization alone).
///
/// Until the O5 review this was `#[inline(never)]`, which the emitter cannot express: rustc
/// then compiles the loop once, out of line, vectorized (NEON), while this `for`-range loop with
/// a conditional assignment, inlined into `line_mul`, stays a scalar loop with a branch per
/// bit — 16 vs 78 ns per `line_mul` on M5, a gap of loop shape, not of specialization. The same
/// loop inlined with a select-shaped body (`acc = if bit { acc ^ a << i } else { acc }`) runs
/// at 11 ns, as a `while` loop at 12 ns: the route to that gain is the loop's printing (optimizer
/// design §6.3 Merge; see the O5 review report), not P20's call-site specialization.
pub fn clmul_lo(a: u64, b: u64) -> u64 {
    let mut acc = 0u64;
    for i in 0..64u32 {
        if (b >> i) & 1 == 1 {
            acc ^= a.wrapping_shl(i);
        }
    }
    acc
}

/// P20: `poly3_mul(a, [1, c, 0])` specialized at the call site: of the six carry-less
/// products, `clmul(x, 1) = x` and `clmul(x, 0) = 0` are known.
#[inline(never)]
pub fn line_mul(a: &[u64; 3], c: u64) -> [u64; 3] {
    [a[0], clmul_lo(a[0], c) ^ a[1], clmul_lo(a[1], c) ^ a[2]]
}

/// Must-reject variants of P15-P20 (the native counterparts of
/// `sandblaster/front/tests/opt_corpus/must_reject.rs`): the harness's `check-reject`
/// mode asserts that the differential checks catch every one of them, so "checks first" can
/// reject a wrong candidate.
pub mod reject {
    use super::*;

    /// P15: the leaf count never checked.
    #[inline(never)]
    pub fn tree_root(height: u32, leaves: &[u64]) -> Option<u64> {
        if height > 12 || leaves.is_empty() {
            return None;
        }
        let mut acc = leaves[0];
        for _ in 0..height {
            acc = tree_node(acc, acc);
        }
        Some(acc)
    }
    /// P15 (subtle): a correct root, but a wrong leaf count accepted when it is one short.
    #[inline(never)]
    pub fn tree_root_len(height: u32, leaves: &[u64]) -> Option<u64> {
        if height > 12 || height == 0 || leaves.len() + 1 != 1usize << height {
            return super::tree_root(height, leaves);
        }
        let mut v = leaves.to_vec();
        v.push(0);
        super::tree_root(height, &v)
    }
    /// P16: the sibling side decided by bit `i + 1`.
    #[inline(never)]
    pub fn batch_roots(leaves: &[u64; 8], indices: &[u64; 8], siblings: &[[u64; 20]; 8]) -> [u64; 8] {
        let shifted: [u64; 8] = core::array::from_fn(|k| indices[k] >> 1);
        super::batch_roots(leaves, &shifted, siblings)
    }
    /// P17: the wrong reduction polynomial (0x1002B).
    #[inline(never)]
    pub fn gf16_mul_block(c: u16, block: &[u8; 64]) -> [u8; 64] {
        let dbl = |a: u16| -> u16 {
            let x = (a as u32) << 1;
            (if x >= 0x1_0000 { (x - 0x1_0000) ^ 0x2b } else { x }) as u16
        };
        let mut out = [0u8; 64];
        for i in 0..32 {
            let v = block[i] as u16 | ((block[i + 32] as u16) << 8);
            let (mut acc, mut x) = (0u16, v);
            for j in 0..16 {
                if (c >> j) & 1 == 1 {
                    acc ^= x;
                }
                x = dbl(x);
            }
            out[i] = acc as u8;
            out[i + 32] = (acc >> 8) as u8;
        }
        out
    }
    /// P18: the last carry dropped from the top limb.
    #[inline(never)]
    pub fn mul_carry(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
        let mut r = super::mul_carry(a, b);
        r[7] = ((a[3] & ((1 << 28) - 1)) * (b[3] & ((1 << 28) - 1))) >> 28;
        r
    }
    /// P20: the `a[2]` term dropped.
    #[inline(never)]
    pub fn line_mul(a: &[u64; 3], c: u64) -> [u64; 3] {
        [a[0], clmul_lo(a[0], c) ^ a[1], clmul_lo(a[1], c)]
    }
}
