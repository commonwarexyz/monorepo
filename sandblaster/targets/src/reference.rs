//! Independent reference implementations of the 256/512-bit x86 models
//! (MODELS.md §10.8).
//!
//! These are **not** transcriptions of the SDM: each one computes the
//! intrinsic's documented result a different way from its model in
//! [`crate::x86_64`] (chunked iterators instead of bit-slice accessors,
//! `rotate_left`/`checked_shl` instead of the SDM's shift pairs, a bitsliced
//! truth table for VPTERNLOG, Russian-peasant multiplication and a
//! brute-force inverse table for GFNI, `count_ones` parity, 128-bit
//! arithmetic for IFMA, a concatenated table for the two-table permutes, a
//! nibble table for the population counts). [`crate::consistency`] compares
//! every wide model with its reference on the diff harness (corner values +
//! random cases + every immediate): locally that is the check that the
//! transcription says what the Intel intrinsics guide says, and on a CPU
//! without the feature it is the model's recorded consistency evidence
//! (`pending-hardware`). The hardware campaign remains the validation.
#![forbid(unsafe_code)]

use std::sync::OnceLock;

fn lanes32<const N: usize>(v: &[u8; N]) -> Vec<u32> {
    v.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)).collect()
}

fn lanes64<const N: usize>(v: &[u8; N]) -> Vec<u64> {
    v.as_chunks::<8>().0.iter().map(|c| u64::from_le_bytes(*c)).collect()
}

fn lanes16<const N: usize>(v: &[u8; N]) -> Vec<u16> {
    v.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect()
}

fn pack32<const N: usize>(l: impl IntoIterator<Item = u32>) -> [u8; N] {
    let mut out = [0u8; N];
    for (c, x) in out.as_chunks_mut::<4>().0.iter_mut().zip(l) {
        *c = x.to_le_bytes();
    }
    out
}

fn pack64<const N: usize>(l: impl IntoIterator<Item = u64>) -> [u8; N] {
    let mut out = [0u8; N];
    for (c, x) in out.as_chunks_mut::<8>().0.iter_mut().zip(l) {
        *c = x.to_le_bytes();
    }
    out
}

fn zip32<const N: usize>(a: [u8; N], b: [u8; N], f: impl Fn(u32, u32) -> u32) -> [u8; N] {
    pack32(lanes32(&a).into_iter().zip(lanes32(&b)).map(|(x, y)| f(x, y)))
}

fn zip64<const N: usize>(a: [u8; N], b: [u8; N], f: impl Fn(u64, u64) -> u64) -> [u8; N] {
    pack64(lanes64(&a).into_iter().zip(lanes64(&b)).map(|(x, y)| f(x, y)))
}

fn map32<const N: usize>(a: [u8; N], f: impl Fn(u32) -> u32) -> [u8; N] {
    pack32(lanes32(&a).into_iter().map(f))
}

fn map64<const N: usize>(a: [u8; N], f: impl Fn(u64) -> u64) -> [u8; N] {
    pack64(lanes64(&a).into_iter().map(f))
}

/// Bitsliced truth table: over whole 64-bit words, OR the minterms selected
/// by `imm` (element size is irrelevant without masking).
fn ternlog<const N: usize>(a: [u8; N], b: [u8; N], c: [u8; N], imm: i32) -> [u8; N] {
    let (x, y, z) = (lanes64(&a), lanes64(&b), lanes64(&c));
    pack64((0..N / 8).map(|i| {
        (0..8).filter(|m| imm >> m & 1 == 1).fold(0u64, |acc, m| {
            let pick = |v: u64, bit: i32| if m & bit != 0 { v } else { !v };
            acc | (pick(x[i], 4) & pick(y[i], 2) & pick(z[i], 1))
        })
    }))
}

fn shl32(x: u32, c: u64) -> u32 {
    u32::try_from(c).ok().and_then(|c| x.checked_shl(c)).unwrap_or(0)
}
fn shr32(x: u32, c: u64) -> u32 {
    u32::try_from(c).ok().and_then(|c| x.checked_shr(c)).unwrap_or(0)
}
fn shl64(x: u64, c: u64) -> u64 {
    u32::try_from(c).ok().and_then(|c| x.checked_shl(c)).unwrap_or(0)
}
fn shr64(x: u64, c: u64) -> u64 {
    u32::try_from(c).ok().and_then(|c| x.checked_shr(c)).unwrap_or(0)
}

/// Per 128-bit block: the table lookup of PSHUFB.
fn pshufb<const N: usize>(a: [u8; N], b: [u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    for ((o, t), c) in out.as_chunks_mut::<16>().0.iter_mut().zip(a.as_chunks::<16>().0).zip(b.as_chunks::<16>().0) {
        for (oi, &ci) in o.iter_mut().zip(c) {
            *oi = if ci >= 0x80 { 0 } else { t[(ci % 16) as usize] };
        }
    }
    out
}

fn blocks<const N: usize>(v: &[u8; N]) -> Vec<[u8; 16]> {
    v.as_chunks::<16>().0.to_vec()
}

fn unblocks<const N: usize>(bs: &[[u8; 16]]) -> [u8; N] {
    let mut out = [0u8; N];
    for (o, b) in out.as_chunks_mut::<16>().0.iter_mut().zip(bs) {
        *o = *b;
    }
    out
}

fn shuf128(a: [u8; 64], b: [u8; 64], imm: i32) -> [u8; 64] {
    let (ba, bb) = (blocks(&a), blocks(&b));
    let sel = |k: i32| (imm >> (2 * k) & 3) as usize;
    unblocks(&[ba[sel(0)], ba[sel(1)], bb[sel(2)], bb[sel(3)]])
}

/// Per 128-bit block, interleave elements `from..from + half` of `a` and `b`.
fn unpack32<const N: usize>(a: [u8; N], b: [u8; N], high: bool) -> [u8; N] {
    let (x, y) = (lanes32(&a), lanes32(&b));
    let mut out = Vec::new();
    for blk in 0..N / 16 {
        let base = 4 * blk + if high { 2 } else { 0 };
        out.extend([x[base], y[base], x[base + 1], y[base + 1]]);
    }
    pack32(out)
}

fn unpack64<const N: usize>(a: [u8; N], b: [u8; N], high: bool) -> [u8; N] {
    let (x, y) = (lanes64(&a), lanes64(&b));
    let mut out = Vec::new();
    for blk in 0..N / 16 {
        let e = 2 * blk + usize::from(high);
        out.extend([x[e], y[e]]);
    }
    pack64(out)
}

/// GF(2^8) multiplication, Russian-peasant style (shift, conditional xor 0x1B).
pub fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 == 1 {
            p ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// The inverse table by exhaustive search (`inv[0] = 0`).
pub fn gf_inv_table() -> &'static [u8; 256] {
    static T: OnceLock<[u8; 256]> = OnceLock::new();
    T.get_or_init(|| {
        let mut t = [0u8; 256];
        for x in 1..=255u8 {
            t[x as usize] = (1..=255u8).find(|&y| gf_mul(x, y) == 1).expect("GF(2^8)* is a group");
        }
        t
    })
}

/// `A·x + b` with row `i` of the matrix in byte `7 - i` and parity by `count_ones`.
fn affine(m: u64, x: u8, b: i32) -> u8 {
    let rows = m.to_be_bytes(); // rows[i] = byte 7 - i
    (0..8).fold(0u8, |acc, i| acc | ((((rows[i] & x).count_ones() & 1) as u8 ^ (b >> i & 1) as u8) << i))
}

fn affine_vec<const N: usize>(x: [u8; N], a: [u8; N], b: i32, inv: bool) -> [u8; N] {
    let mats = lanes64(&a);
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        let v = if inv { gf_inv_table()[x[i] as usize] } else { x[i] };
        *o = affine(mats[i / 8], v, b);
    }
    out
}

fn nibble_popcount(x: u64) -> u64 {
    const T: [u8; 16] = [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4];
    (0..16).map(|k| T[((x >> (4 * k)) & 15) as usize] as u64).sum()
}

fn blend<const N: usize, const W: usize>(k: u64, a: [u8; N], b: [u8; N]) -> [u8; N] {
    let mut out = a;
    for j in 0..N / W {
        if k >> j & 1 == 1 {
            out[W * j..W * (j + 1)].copy_from_slice(&b[W * j..W * (j + 1)]);
        }
    }
    out
}

fn masked<const N: usize, const W: usize>(src: Option<[u8; N]>, k: u64, a: [u8; N]) -> [u8; N] {
    blend::<N, W>(k, src.unwrap_or([0; N]), a)
}

fn alignr256(a: [u8; 32], b: [u8; 32], imm: i32) -> [u8; 32] {
    let mut out = [0u8; 32];
    for blk in 0..2 {
        let c: Vec<u8> = b[16 * blk..16 * blk + 16].iter().chain(&a[16 * blk..16 * blk + 16]).copied().collect();
        for i in 0..16 {
            out[16 * blk + i] = c.get(i + imm as usize).copied().unwrap_or(0);
        }
    }
    out
}

macro_rules! refs {
    ($( $(#[$doc:meta])* fn $name:ident($($arg:ident : $ty:ty),*) -> $ret:ty $body:block )*) => {
        $( $(#[$doc])* pub fn $name($($arg: $ty),*) -> $ret $body )*
        /// The names of the models with a reference implementation, in
        /// definition order.
        pub const NAMES: &[&str] = &[$(stringify!($name)),*];
    };
}

type Z = [u8; 64];
type Y = [u8; 32];
type X = [u8; 16];

refs! {
    /// Copy.
    fn _mm512_loadu_si512(mem: &Z) -> Z { *mem }
    /// Copy.
    fn _mm512_storeu_si512(a: Z) -> Z { a }
    /// Wrapping dword add.
    fn _mm512_add_epi32(a: Z, b: Z) -> Z { zip32(a, b, u32::wrapping_add) }
    /// Wrapping qword add.
    fn _mm512_add_epi64(a: Z, b: Z) -> Z { zip64(a, b, u64::wrapping_add) }
    /// Wrapping dword subtract.
    fn _mm512_sub_epi32(a: Z, b: Z) -> Z { zip32(a, b, u32::wrapping_sub) }
    /// Wrapping qword subtract.
    fn _mm512_sub_epi64(a: Z, b: Z) -> Z { zip64(a, b, u64::wrapping_sub) }
    /// Xor on qwords.
    fn _mm512_xor_si512(a: Z, b: Z) -> Z { zip64(a, b, |x, y| x ^ y) }
    /// And on qwords.
    fn _mm512_and_si512(a: Z, b: Z) -> Z { zip64(a, b, |x, y| x & y) }
    /// Or on qwords.
    fn _mm512_or_si512(a: Z, b: Z) -> Z { zip64(a, b, |x, y| x | y) }
    /// `!a & b` on qwords.
    fn _mm512_andnot_si512(a: Z, b: Z) -> Z { zip64(a, b, |x, y| !x & y) }
    /// Bitsliced truth table.
    fn _mm512_ternarylogic_epi32(a: Z, b: Z, c: Z, imm8: i32) -> Z { ternlog(a, b, c, imm8) }
    /// Bitsliced truth table.
    fn _mm512_ternarylogic_epi64(a: Z, b: Z, c: Z, imm8: i32) -> Z { ternlog(a, b, c, imm8) }
    /// `rotate_left(imm mod 32)`.
    fn _mm512_rol_epi32(a: Z, imm8: i32) -> Z { map32(a, |x| x.rotate_left(imm8 as u32 % 32)) }
    /// `rotate_right(imm mod 32)`.
    fn _mm512_ror_epi32(a: Z, imm8: i32) -> Z { map32(a, |x| x.rotate_right(imm8 as u32 % 32)) }
    /// `rotate_left(imm mod 64)`.
    fn _mm512_rol_epi64(a: Z, imm8: i32) -> Z { map64(a, |x| x.rotate_left(imm8 as u32 % 64)) }
    /// `rotate_right(imm mod 64)`.
    fn _mm512_ror_epi64(a: Z, imm8: i32) -> Z { map64(a, |x| x.rotate_right(imm8 as u32 % 64)) }
    /// `rotate_left(b mod 32)`.
    fn _mm512_rolv_epi32(a: Z, b: Z) -> Z { zip32(a, b, |x, c| x.rotate_left(c % 32)) }
    /// `rotate_right(b mod 32)`.
    fn _mm512_rorv_epi32(a: Z, b: Z) -> Z { zip32(a, b, |x, c| x.rotate_right(c % 32)) }
    /// `rotate_left(b mod 64)`.
    fn _mm512_rolv_epi64(a: Z, b: Z) -> Z { zip64(a, b, |x, c| x.rotate_left((c % 64) as u32)) }
    /// `rotate_right(b mod 64)`.
    fn _mm512_rorv_epi64(a: Z, b: Z) -> Z { zip64(a, b, |x, c| x.rotate_right((c % 64) as u32)) }
    /// `checked_shl` (0 past the width).
    fn _mm512_slli_epi32(a: Z, imm8: i32) -> Z { map32(a, |x| shl32(x, imm8 as u64)) }
    /// `checked_shr`.
    fn _mm512_srli_epi32(a: Z, imm8: i32) -> Z { map32(a, |x| shr32(x, imm8 as u64)) }
    /// `checked_shl`.
    fn _mm512_slli_epi64(a: Z, imm8: i32) -> Z { map64(a, |x| shl64(x, imm8 as u64)) }
    /// `checked_shr`.
    fn _mm512_srli_epi64(a: Z, imm8: i32) -> Z { map64(a, |x| shr64(x, imm8 as u64)) }
    /// `checked_shl` by the full 64-bit count.
    fn _mm512_sllv_epi64(a: Z, count: Z) -> Z { zip64(a, count, shl64) }
    /// `checked_shr` by the full 64-bit count.
    fn _mm512_srlv_epi64(a: Z, count: Z) -> Z { zip64(a, count, shr64) }
    /// Per-block table lookup.
    fn _mm512_shuffle_epi8(a: Z, b: Z) -> Z { pshufb(a, b) }
    /// `a[idx % 16]`.
    fn _mm512_permutexvar_epi32(idx: Z, a: Z) -> Z { let t = lanes32(&a); map32(idx, |i| t[(i % 16) as usize]) }
    /// `a[idx % 8]`.
    fn _mm512_permutexvar_epi64(idx: Z, a: Z) -> Z { let t = lanes64(&a); map64(idx, |i| t[(i % 8) as usize]) }
    /// `(a ++ b)[idx % 16]`.
    fn _mm512_permutex2var_epi64(a: Z, idx: Z, b: Z) -> Z {
        let t: Vec<u64> = lanes64(&a).into_iter().chain(lanes64(&b)).collect();
        map64(idx, |i| t[(i % 16) as usize])
    }
    /// 128-bit block selection.
    fn _mm512_shuffle_i32x4(a: Z, b: Z, imm8: i32) -> Z { shuf128(a, b, imm8) }
    /// 128-bit block selection.
    fn _mm512_shuffle_i64x2(a: Z, b: Z, imm8: i32) -> Z { shuf128(a, b, imm8) }
    /// Low interleave per block.
    fn _mm512_unpacklo_epi32(a: Z, b: Z) -> Z { unpack32(a, b, false) }
    /// High interleave per block.
    fn _mm512_unpackhi_epi32(a: Z, b: Z) -> Z { unpack32(a, b, true) }
    /// Low interleave per block.
    fn _mm512_unpacklo_epi64(a: Z, b: Z) -> Z { unpack64(a, b, false) }
    /// High interleave per block.
    fn _mm512_unpackhi_epi64(a: Z, b: Z) -> Z { unpack64(a, b, true) }
    /// The bytes of `a` repeated.
    fn _mm512_set1_epi32(a: i32) -> Z { core::array::from_fn(|i| a.to_le_bytes()[i % 4]) }
    /// The bytes of `a` repeated.
    fn _mm512_set1_epi64(a: i64) -> Z { core::array::from_fn(|i| a.to_le_bytes()[i % 8]) }
    /// Copy `b`'s elements where `k` is set.
    fn _mm512_mask_blend_epi32(k: u16, a: Z, b: Z) -> Z { blend::<64, 4>(k as u64, a, b) }
    /// Copy `b`'s elements where `k` is set.
    fn _mm512_mask_blend_epi64(k: u8, a: Z, b: Z) -> Z { blend::<64, 8>(k as u64, a, b) }
    /// Fold of unsigned `<`.
    fn _mm512_cmplt_epu64_mask(a: Z, b: Z) -> u8 {
        lanes64(&a).iter().zip(lanes64(&b)).enumerate().fold(0, |k, (j, (x, y))| k | (u8::from(*x < y) << j))
    }
    /// Fold of `==`.
    fn _mm512_cmpeq_epi64_mask(a: Z, b: Z) -> u8 {
        lanes64(&a).iter().zip(lanes64(&b)).enumerate().fold(0, |k, (j, (x, y))| k | (u8::from(*x == y) << j))
    }
    /// Fold of `==`.
    fn _mm512_cmpeq_epi32_mask(a: Z, b: Z) -> u16 {
        lanes32(&a).iter().zip(lanes32(&b)).enumerate().fold(0, |k, (j, (x, y))| k | (u16::from(*x == y) << j))
    }
    /// Zero, then copy `a`'s elements where `k` is set.
    fn _mm512_maskz_mov_epi32(k: u16, a: Z) -> Z { masked::<64, 4>(None, k as u64, a) }
    /// `src`, then copy `a`'s elements where `k` is set.
    fn _mm512_mask_mov_epi32(src: Z, k: u16, a: Z) -> Z { masked::<64, 4>(Some(src), k as u64, a) }
    /// Zero, then copy `a`'s elements where `k` is set.
    fn _mm512_maskz_mov_epi64(k: u8, a: Z) -> Z { masked::<64, 8>(None, k as u64, a) }
    /// `src`, then copy `a`'s elements where `k` is set.
    fn _mm512_mask_mov_epi64(src: Z, k: u8, a: Z) -> Z { masked::<64, 8>(Some(src), k as u64, a) }
    /// `wrapping_mul`.
    fn _mm512_mullo_epi64(a: Z, b: Z) -> Z { zip64(a, b, u64::wrapping_mul) }
    /// Product of the truncated low halves.
    fn _mm512_mul_epu32(a: Z, b: Z) -> Z { zip64(a, b, |x, y| (x as u32 as u64) * (y as u32 as u64)) }
    /// Bitsliced truth table.
    fn _mm256_ternarylogic_epi32(a: Y, b: Y, c: Y, imm8: i32) -> Y { ternlog(a, b, c, imm8) }
    /// Bitsliced truth table.
    fn _mm256_ternarylogic_epi64(a: Y, b: Y, c: Y, imm8: i32) -> Y { ternlog(a, b, c, imm8) }
    /// `rotate_left(imm mod 32)`.
    fn _mm256_rol_epi32(a: Y, imm8: i32) -> Y { map32(a, |x| x.rotate_left(imm8 as u32 % 32)) }
    /// `rotate_right(imm mod 32)`.
    fn _mm256_ror_epi32(a: Y, imm8: i32) -> Y { map32(a, |x| x.rotate_right(imm8 as u32 % 32)) }
    /// `rotate_left(imm mod 64)`.
    fn _mm256_rol_epi64(a: Y, imm8: i32) -> Y { map64(a, |x| x.rotate_left(imm8 as u32 % 64)) }
    /// `rotate_right(imm mod 64)`.
    fn _mm256_ror_epi64(a: Y, imm8: i32) -> Y { map64(a, |x| x.rotate_right(imm8 as u32 % 64)) }
    /// `a + lo52(lo52(b) · lo52(c))` with 128-bit arithmetic.
    fn _mm512_madd52lo_epu64(a: Z, b: Z, c: Z) -> Z { madd52(a, b, c, false) }
    /// `a + hi52(lo52(b) · lo52(c))`.
    fn _mm512_madd52hi_epu64(a: Z, b: Z, c: Z) -> Z { madd52(a, b, c, true) }
    /// As the 512-bit form.
    fn _mm256_madd52lo_epu64(a: Y, b: Y, c: Y) -> Y { madd52(a, b, c, false) }
    /// As the 512-bit form.
    fn _mm256_madd52hi_epu64(a: Y, b: Y, c: Y) -> Y { madd52(a, b, c, true) }
    /// Russian-peasant multiplication per byte.
    fn _mm512_gf2p8mul_epi8(a: Z, b: Z) -> Z { core::array::from_fn(|i| gf_mul(a[i], b[i])) }
    /// Russian-peasant multiplication per byte.
    fn _mm256_gf2p8mul_epi8(a: Y, b: Y) -> Y { core::array::from_fn(|i| gf_mul(a[i], b[i])) }
    /// Russian-peasant multiplication per byte.
    fn _mm_gf2p8mul_epi8(a: X, b: X) -> X { core::array::from_fn(|i| gf_mul(a[i], b[i])) }
    /// Matrix-vector product with `count_ones` parity.
    fn _mm512_gf2p8affine_epi64_epi8(x: Z, a: Z, b: i32) -> Z { affine_vec(x, a, b, false) }
    /// Matrix-vector product with `count_ones` parity.
    fn _mm256_gf2p8affine_epi64_epi8(x: Y, a: Y, b: i32) -> Y { affine_vec(x, a, b, false) }
    /// Matrix-vector product with `count_ones` parity.
    fn _mm_gf2p8affine_epi64_epi8(x: X, a: X, b: i32) -> X { affine_vec(x, a, b, false) }
    /// The product applied to the brute-force inverse.
    fn _mm512_gf2p8affineinv_epi64_epi8(x: Z, a: Z, b: i32) -> Z { affine_vec(x, a, b, true) }
    /// The product applied to the brute-force inverse.
    fn _mm256_gf2p8affineinv_epi64_epi8(x: Y, a: Y, b: i32) -> Y { affine_vec(x, a, b, true) }
    /// The product applied to the brute-force inverse.
    fn _mm_gf2p8affineinv_epi64_epi8(x: X, a: X, b: i32) -> X { affine_vec(x, a, b, true) }
    /// `a[idx % 64]`.
    fn _mm512_permutexvar_epi8(idx: Z, a: Z) -> Z { core::array::from_fn(|j| a[(idx[j] % 64) as usize]) }
    /// `(a ++ b)[idx % 128]`.
    fn _mm512_permutex2var_epi8(a: Z, idx: Z, b: Z) -> Z {
        core::array::from_fn(|j| { let i = (idx[j] % 128) as usize; if i < 64 { a[i] } else { b[i - 64] } })
    }
    /// The low byte of the qword rotated right by the control.
    fn _mm512_multishift_epi64_epi8(a: Z, b: Z) -> Z {
        let t = lanes64(&b);
        core::array::from_fn(|i| t[i / 8].rotate_right((a[i] % 64) as u32) as u8)
    }
    /// `(a << s) | (b >> (64 - s))`, `a` for `s = 0`.
    fn _mm512_shldv_epi64(a: Z, b: Z, c: Z) -> Z {
        let (x, y, z) = (lanes64(&a), lanes64(&b), lanes64(&c));
        pack64((0..8).map(|j| { let s = (z[j] % 64) as u32; if s == 0 { x[j] } else { (x[j] << s) | (y[j] >> (64 - s)) } }))
    }
    /// `(a >> s) | (b << (64 - s))`, `a` for `s = 0`.
    fn _mm512_shrdv_epi64(a: Z, b: Z, c: Z) -> Z {
        let (x, y, z) = (lanes64(&a), lanes64(&b), lanes64(&c));
        pack64((0..8).map(|j| { let s = (z[j] % 64) as u32; if s == 0 { x[j] } else { (x[j] >> s) | (y[j] << (64 - s)) } }))
    }
    /// As the qword form on dwords.
    fn _mm512_shldv_epi32(a: Z, b: Z, c: Z) -> Z {
        let (x, y, z) = (lanes32(&a), lanes32(&b), lanes32(&c));
        pack32((0..16).map(|j| { let s = z[j] % 32; if s == 0 { x[j] } else { (x[j] << s) | (y[j] >> (32 - s)) } }))
    }
    /// As the qword form on dwords.
    fn _mm512_shrdv_epi32(a: Z, b: Z, c: Z) -> Z {
        let (x, y, z) = (lanes32(&a), lanes32(&b), lanes32(&c));
        pack32((0..16).map(|j| { let s = z[j] % 32; if s == 0 { x[j] } else { (x[j] >> s) | (y[j] << (32 - s)) } }))
    }
    /// `(a << s) | (b >> (64 - s))` with `s = imm mod 64`.
    fn _mm512_shldi_epi64(a: Z, b: Z, imm8: i32) -> Z {
        let s = (imm8 % 64) as u32;
        zip64(a, b, |x, y| if s == 0 { x } else { (x << s) | (y >> (64 - s)) })
    }
    /// `(a << s) | (b >> (32 - s))` with `s = imm mod 32`.
    fn _mm512_shldi_epi32(a: Z, b: Z, imm8: i32) -> Z {
        let s = (imm8 % 32) as u32;
        zip32(a, b, |x, y| if s == 0 { x } else { (x << s) | (y >> (32 - s)) })
    }
    /// Nibble-table population count.
    fn _mm512_popcnt_epi64(a: Z) -> Z { map64(a, nibble_popcount) }
    /// Nibble-table population count.
    fn _mm512_popcnt_epi32(a: Z) -> Z { map32(a, |x| nibble_popcount(x as u64) as u32) }
    /// Nibble-table population count.
    fn _mm512_popcnt_epi8(a: Z) -> Z { core::array::from_fn(|i| nibble_popcount(a[i] as u64) as u8) }
    /// Nibble-table population count.
    fn _mm512_popcnt_epi16(a: Z) -> Z {
        let w = lanes16(&a);
        core::array::from_fn(|i| (nibble_popcount(w[i / 2] as u64) as u16).to_le_bytes()[i % 2])
    }
    /// Copy.
    fn _mm256_loadu_si256(mem: &Y) -> Y { *mem }
    /// Copy.
    fn _mm256_storeu_si256(a: Y) -> Y { a }
    /// Wrapping dword add.
    fn _mm256_add_epi32(a: Y, b: Y) -> Y { zip32(a, b, u32::wrapping_add) }
    /// Wrapping qword add.
    fn _mm256_add_epi64(a: Y, b: Y) -> Y { zip64(a, b, u64::wrapping_add) }
    /// Xor on qwords.
    fn _mm256_xor_si256(a: Y, b: Y) -> Y { zip64(a, b, |x, y| x ^ y) }
    /// And on qwords.
    fn _mm256_and_si256(a: Y, b: Y) -> Y { zip64(a, b, |x, y| x & y) }
    /// Or on qwords.
    fn _mm256_or_si256(a: Y, b: Y) -> Y { zip64(a, b, |x, y| x | y) }
    /// Per-block table lookup.
    fn _mm256_shuffle_epi8(a: Y, b: Y) -> Y { pshufb(a, b) }
    /// `a[idx % 8]` (table first).
    fn _mm256_permutevar8x32_epi32(a: Y, idx: Y) -> Y { let t = lanes32(&a); map32(idx, |i| t[(i % 8) as usize]) }
    /// `checked_shl`.
    fn _mm256_slli_epi32(a: Y, imm8: i32) -> Y { map32(a, |x| shl32(x, imm8 as u64)) }
    /// `checked_shr`.
    fn _mm256_srli_epi32(a: Y, imm8: i32) -> Y { map32(a, |x| shr32(x, imm8 as u64)) }
    /// `checked_shl`.
    fn _mm256_slli_epi64(a: Y, imm8: i32) -> Y { map64(a, |x| shl64(x, imm8 as u64)) }
    /// `checked_shr`.
    fn _mm256_srli_epi64(a: Y, imm8: i32) -> Y { map64(a, |x| shr64(x, imm8 as u64)) }
    /// Copy `b`'s dwords where `imm` is set.
    fn _mm256_blend_epi32(a: Y, b: Y, imm8: i32) -> Y { blend::<32, 4>(imm8 as u64, a, b) }
    /// Per block: bytes `imm..imm + 16` of `b ++ a` (zero past the end).
    fn _mm256_alignr_epi8(a: Y, b: Y, imm8: i32) -> Y { alignr256(a, b, imm8) }
    /// The bytes of `a` repeated.
    fn _mm256_set1_epi32(a: i32) -> Y { core::array::from_fn(|i| a.to_le_bytes()[i % 4]) }
    /// The bytes of `a` repeated.
    fn _mm256_set1_epi64x(a: i64) -> Y { core::array::from_fn(|i| a.to_le_bytes()[i % 8]) }
}

fn madd52<const N: usize>(a: [u8; N], b: [u8; N], c: [u8; N], high: bool) -> [u8; N] {
    const LOW: u128 = 1 << 52;
    let (acc, x, y) = (lanes64(&a), lanes64(&b), lanes64(&c));
    pack64((0..N / 8).map(|j| {
        let p = (x[j] as u128 % LOW) * (y[j] as u128 % LOW);
        let part = if high { p / LOW % LOW } else { p % LOW };
        acc[j].wrapping_add(part as u64)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_cover_the_wide_registry() {
        let wide: Vec<&str> = crate::registry::X86_64[crate::registry::ROUND0_X86_64..].iter().map(|m| m.name).collect();
        assert_eq!(NAMES.to_vec(), wide);
    }

    #[test]
    fn gf_helpers() {
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
        assert_eq!(gf_inv_table()[0x53], 0xca);
        assert_eq!(affine(0x0102_0408_1020_4080, 0x5a, 0), 0x5a);
    }
}
