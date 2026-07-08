//! Vectorized dense NTT for the Goldilocks field.
//!
//! Each column of a row-major `rows x cols` matrix is an independent NTT lane, and
//! the butterfly inner loop walks contiguous columns with a shared twiddle. That is
//! the natural SIMD axis: broadcast the twiddle, then process `WIDTH` contiguous
//! columns per instruction with packed field arithmetic, handling the
//! `cols % WIDTH` remainder with the scalar field.
//!
//! The packed `add`/`sub`/`mul` mirror [`super::F`]'s `add_inner`/`sub_inner`/
//! `reduce_128` operation-for-operation, so the vector result is bit-identical to the
//! scalar field (verified exhaustively against [`super::F`] in tests). Dispatch picks
//! AVX2 (x86-64), NEON (aarch64), or the scalar fallback once per NTT.

use super::F;
// `P` is used only by the arch-specific SIMD submodules; gate its import to the
// same conditions so the scalar-only build (no_std x86, or non-x86/non-aarch64)
// does not see an unused import.
#[cfg(any(all(target_arch = "x86_64", feature = "std"), target_arch = "aarch64"))]
use super::P;
use crate::algebra::FieldNTT;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
#[cfg(feature = "std")]
use std::vec::Vec;

/// `2^32 - 1`, i.e. `2^64 mod P`. Used throughout the Goldilocks reduction.
#[allow(dead_code)]
const EPSILON: u64 = 0xFFFF_FFFF;

/// Reinterpret a slice of field elements as raw `u64`s.
///
/// Sound because [`F`] is `#[repr(transparent)]` over `u64`.
#[allow(dead_code)]
#[inline]
const fn as_u64_mut(data: &mut [F]) -> &mut [u64] {
    let len = data.len();
    // SAFETY: `F` is `#[repr(transparent)]` over `u64`, so the layouts match.
    unsafe { core::slice::from_raw_parts_mut(data.as_mut_ptr().cast::<u64>(), len) }
}

/// Dense NTT (inverse when `FORWARD` is false) over a row-major `rows x cols` slice.
pub(super) fn ntt_dense<const FORWARD: bool>(rows: usize, cols: usize, data: &mut [F]) {
    cfg_if::cfg_if! {
        if #[cfg(all(target_arch = "x86_64", feature = "std"))] {
            if std::is_x86_feature_detected!("avx2") {
                // SAFETY: avx2 was just detected at runtime.
                unsafe { avx2::ntt_dense::<FORWARD>(rows, cols, data) }
            } else {
                crate::ntt::ntt_dense_scalar::<FORWARD, F>(rows, cols, data)
            }
        } else if #[cfg(target_arch = "aarch64")] {
            // SAFETY: NEON is part of the aarch64 baseline, so it is always present.
            unsafe { neon::ntt_dense::<FORWARD>(rows, cols, data) }
        } else {
            crate::ntt::ntt_dense_scalar::<FORWARD, F>(rows, cols, data)
        }
    }
}

/// Compute the per-stage twiddle schedule (shared by every backend).
///
/// Returns, for each stage in application order, the base twiddle whose powers the
/// butterflies of that stage step through.
#[allow(dead_code)]
fn twiddle_stages<const FORWARD: bool>(lg_rows: usize) -> Vec<(usize, F)> {
    use crate::algebra::{Additive, Ring};
    let w = {
        let w = F::root_of_unity(lg_rows as u8).expect("too many rows to perform NTT");
        if FORWARD {
            w
        } else {
            w.exp(&[(1 << lg_rows) - 1])
        }
    };
    let mut out = vec![(0usize, F::zero()); lg_rows];
    let mut w_i = w;
    for i in (0..lg_rows).rev() {
        out[i] = (i, w_i);
        w_i = w_i * w_i;
    }
    if !FORWARD {
        out.reverse();
    }
    out
}

// Gated on `std` to match the dispatch in `ntt_dense`: runtime AVX2 detection
// (`is_x86_feature_detected!`) is only available with `std`, so without it this
// module would be uncallable dead code.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
mod avx2 {
    use super::{as_u64_mut, twiddle_stages, F, P};
    use crate::algebra::{FieldNTT, Ring};
    use core::arch::x86_64::*;

    /// Number of `u64` lanes per AVX2 register.
    const WIDTH: usize = 4;

    #[inline(always)]
    unsafe fn load(p: *const u64) -> __m256i {
        _mm256_loadu_si256(p.cast::<__m256i>())
    }
    #[inline(always)]
    unsafe fn store(p: *mut u64, v: __m256i) {
        _mm256_storeu_si256(p.cast::<__m256i>(), v);
    }
    #[inline(always)]
    unsafe fn splat(x: u64) -> __m256i {
        _mm256_set1_epi64x(x as i64)
    }
    /// Per-lane unsigned `a < b`, returning an all-ones / all-zeros mask.
    #[inline(always)]
    unsafe fn ult(a: __m256i, b: __m256i) -> __m256i {
        // No unsigned 64-bit compare in AVX2: flip the sign bit and use signed `>`.
        let s = _mm256_set1_epi64x(i64::MIN);
        _mm256_cmpgt_epi64(_mm256_xor_si256(b, s), _mm256_xor_si256(a, s))
    }
    /// Per-lane unsigned `a >= b`.
    #[inline(always)]
    unsafe fn uge(a: __m256i, b: __m256i) -> __m256i {
        _mm256_xor_si256(ult(a, b), _mm256_set1_epi64x(-1))
    }
    /// Per-lane `mask ? t : f` (mask must be all-ones / all-zeros).
    #[inline(always)]
    unsafe fn select(mask: __m256i, t: __m256i, f: __m256i) -> __m256i {
        _mm256_blendv_epi8(f, t, mask)
    }

    /// Field add; mirrors `F::add_inner` (also valid for the partially reduced
    /// operands produced inside the reduction).
    #[inline(always)]
    unsafe fn add(x: __m256i, y: __m256i) -> __m256i {
        let p = splat(P);
        let sum = _mm256_add_epi64(x, y);
        let overflow = ult(sum, x);
        let ge_p = uge(sum, p);
        let cond = _mm256_or_si256(overflow, ge_p);
        select(cond, _mm256_sub_epi64(sum, p), sum)
    }
    /// Field sub; mirrors `F::sub_inner`.
    #[inline(always)]
    unsafe fn sub(x: __m256i, y: __m256i) -> __m256i {
        let p = splat(P);
        let diff = _mm256_sub_epi64(x, y);
        let borrow = ult(x, y);
        select(borrow, _mm256_add_epi64(diff, p), diff)
    }
    /// Widening `64 x 64 -> 128` per lane, returning `(lo, hi)`.
    #[inline(always)]
    unsafe fn mul_wide(a: __m256i, b: __m256i) -> (__m256i, __m256i) {
        let mask32 = _mm256_set1_epi64x(0xFFFF_FFFF);
        let a_h = _mm256_srli_epi64(a, 32);
        let b_h = _mm256_srli_epi64(b, 32);
        // 32x32 -> 64 partial products (mul_epu32 uses the low 32 bits of each lane).
        let ll = _mm256_mul_epu32(a, b);
        let lh = _mm256_mul_epu32(a, b_h);
        let hl = _mm256_mul_epu32(a_h, b);
        let hh = _mm256_mul_epu32(a_h, b_h);
        // Combine columns; each 64-bit add below is overflow-free for 32-bit inputs.
        let ll_hi = _mm256_srli_epi64(ll, 32);
        let t = _mm256_add_epi64(lh, ll_hi);
        let t_lo = _mm256_and_si256(t, mask32);
        let t_hi = _mm256_srli_epi64(t, 32);
        let u = _mm256_add_epi64(hl, t_lo);
        let lo = _mm256_or_si256(
            _mm256_and_si256(ll, mask32),
            _mm256_slli_epi64(_mm256_and_si256(u, mask32), 32),
        );
        let hi = _mm256_add_epi64(_mm256_add_epi64(hh, t_hi), _mm256_srli_epi64(u, 32));
        (lo, hi)
    }
    /// Field mul; mirrors `F::reduce_128(a*b)`.
    #[inline(always)]
    unsafe fn mul(a: __m256i, b: __m256i) -> __m256i {
        let (lo, hi) = mul_wide(a, b);
        let mask32 = _mm256_set1_epi64x(0xFFFF_FFFF);
        // x = lo + mid*2^64 + top*2^96, with 2^64 = EPSILON, 2^96 = -1 (mod P):
        // result = (lo - top) + mid*EPSILON.
        let mid = _mm256_and_si256(hi, mask32);
        let top = _mm256_srli_epi64(hi, 32);
        let beps = _mm256_sub_epi64(_mm256_slli_epi64(mid, 32), mid);
        add(sub(lo, top), beps)
    }
    /// Field halving; mirrors `F::div_2`.
    #[inline(always)]
    unsafe fn div2(x: __m256i) -> __m256i {
        let one = _mm256_set1_epi64x(1);
        let odd = _mm256_cmpeq_epi64(_mm256_and_si256(x, one), one);
        let even = _mm256_srli_epi64(x, 1);
        let addp = _mm256_add_epi64(x, splat(P));
        let carry = ult(addp, x);
        let carry_hi = _mm256_and_si256(carry, _mm256_set1_epi64x(i64::MIN));
        let odd_res = _mm256_or_si256(carry_hi, _mm256_srli_epi64(addp, 1));
        select(odd, odd_res, even)
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn ntt_dense<const FORWARD: bool>(rows: usize, cols: usize, data: &mut [F]) {
        let lg_rows = crate::ntt::dense_ntt_lg_rows(rows, cols, data.len());
        let raw = as_u64_mut(data);
        let ptr = raw.as_mut_ptr();
        let main = cols - cols % WIDTH;
        for (stage, w_stage) in twiddle_stages::<FORWARD>(lg_rows) {
            let skip = 1usize << stage;
            let mut i = 0;
            while i < rows {
                let mut w_j = F::one();
                for j in 0..skip {
                    let base_a = (i + j) * cols;
                    let base_b = (i + j + skip) * cols;
                    let wv = splat(w_j.0);
                    let mut k = 0;
                    while k < main {
                        let pa = ptr.add(base_a + k);
                        let pb = ptr.add(base_b + k);
                        let a = load(pa);
                        let b = load(pb);
                        if FORWARD {
                            let t = mul(wv, b);
                            store(pa, add(a, t));
                            store(pb, sub(a, t));
                        } else {
                            let s = add(a, b);
                            let d = sub(a, b);
                            store(pa, div2(s));
                            store(pb, div2(mul(d, wv)));
                        }
                        k += WIDTH;
                    }
                    // Remainder columns: scalar field, accessed through `ptr` so all
                    // reads/writes share one provenance.
                    for k in main..cols {
                        let a = F(*ptr.add(base_a + k));
                        let b = F(*ptr.add(base_b + k));
                        if FORWARD {
                            let t = w_j * b;
                            *ptr.add(base_a + k) = (a + t).0;
                            *ptr.add(base_b + k) = (a - t).0;
                        } else {
                            *ptr.add(base_a + k) = (a + b).div_2().0;
                            *ptr.add(base_b + k) = ((a - b) * w_j).div_2().0;
                        }
                    }
                    w_j *= &w_stage;
                }
                i += 2 * skip;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{super::EPSILON, add, div2, mul, sub, F, P};
        use crate::algebra::FieldNTT;
        use core::arch::x86_64::*;

        fn lanes_of(
            op: unsafe fn(__m256i, __m256i) -> __m256i,
            a: [u64; 4],
            b: [u64; 4],
        ) -> [u64; 4] {
            // SAFETY: callers gate on `is_x86_feature_detected!("avx2")`.
            unsafe {
                let va = _mm256_loadu_si256(a.as_ptr().cast());
                let vb = _mm256_loadu_si256(b.as_ptr().cast());
                let r = op(va, vb);
                let mut out = [0u64; 4];
                _mm256_storeu_si256(out.as_mut_ptr().cast(), r);
                out
            }
        }

        unsafe fn div2_bin(x: __m256i, _y: __m256i) -> __m256i {
            div2(x)
        }

        fn samples() -> Vec<u64> {
            let mut v = vec![
                0u64,
                1,
                2,
                P - 1,
                P - 2,
                EPSILON,
                EPSILON + 1,
                1 << 32,
                (1 << 32) - 1,
                (1 << 63),
                u64::MAX % P,
                P / 2,
                12345678901234567 % P,
            ];
            // Deterministic pseudo-random canonical elements.
            let mut x = 0x1234_5678_9abc_def0u64;
            for _ in 0..200 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                v.push(x % P);
            }
            v
        }

        #[test]
        fn avx2_field_ops_match_scalar() {
            if !std::is_x86_feature_detected!("avx2") {
                return;
            }
            let s = samples();
            for &a in &s {
                for &b in &s {
                    let aa = [a, b, (a + 1) % P, (b + 2) % P];
                    let bb = [b, a, (b + 3) % P, (a + 5) % P];
                    let exp_add: [u64; 4] = core::array::from_fn(|i| (F(aa[i]) + F(bb[i])).0);
                    let exp_sub: [u64; 4] = core::array::from_fn(|i| (F(aa[i]) - F(bb[i])).0);
                    let exp_mul: [u64; 4] = core::array::from_fn(|i| (F(aa[i]) * F(bb[i])).0);
                    assert_eq!(lanes_of(add, aa, bb), exp_add);
                    assert_eq!(lanes_of(sub, aa, bb), exp_sub);
                    assert_eq!(lanes_of(mul, aa, bb), exp_mul);
                }
            }
        }

        #[test]
        fn avx2_div2_matches_scalar() {
            if !std::is_x86_feature_detected!("avx2") {
                return;
            }
            let s = samples();
            for chunk in s.chunks(4) {
                let mut aa = [0u64; 4];
                aa[..chunk.len()].copy_from_slice(chunk);
                let exp: [u64; 4] = core::array::from_fn(|i| F(aa[i]).div_2().0);
                let got = lanes_of(div2_bin, aa, aa);
                assert_eq!(got, exp);
            }
        }
    }
}

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod dense_tests {
    use super::{ntt_dense, F, P};

    #[cfg(target_arch = "x86_64")]
    fn simd_available() -> bool {
        std::is_x86_feature_detected!("avx2")
    }

    #[cfg(target_arch = "aarch64")]
    const fn simd_available() -> bool {
        true
    }

    fn rand_data(n: usize, seed: u64) -> Vec<F> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                F(x % P)
            })
            .collect()
    }

    /// The dispatched SIMD dense NTT must equal the scalar reference, across directions,
    /// sizes, and SIMD-width remainders.
    #[test]
    fn dense_matches_scalar() {
        if !simd_available() {
            return;
        }
        for lg in [0usize, 1, 2, 4, 8, 12] {
            let rows = 1usize << lg;
            for cols in [1usize, 2, 3, 4, 5, 7, 8, 9, 16, 17, 33, 64] {
                let base = rand_data(rows * cols, (lg as u64) * 1_000 + cols as u64);

                let mut got = base.clone();
                let mut want = base.clone();
                ntt_dense::<true>(rows, cols, &mut got);
                crate::ntt::ntt_dense_scalar::<true, F>(rows, cols, &mut want);
                assert_eq!(got, want, "forward lg={lg} cols={cols}");

                let mut got = base.clone();
                let mut want = base;
                ntt_dense::<false>(rows, cols, &mut got);
                crate::ntt::ntt_dense_scalar::<false, F>(rows, cols, &mut want);
                assert_eq!(got, want, "inverse lg={lg} cols={cols}");
            }
        }
    }

    #[test]
    #[should_panic(expected = "data length must equal rows * cols")]
    fn dense_rejects_short_data() {
        let mut data = vec![F(0); 3];
        ntt_dense::<true>(2, 2, &mut data);
    }

    #[test]
    #[should_panic(expected = "rows should be a non-zero power of 2")]
    fn dense_rejects_zero_rows() {
        let mut data = Vec::new();
        ntt_dense::<true>(0, 0, &mut data);
    }
}

#[cfg(target_arch = "aarch64")]
mod neon {
    use super::{as_u64_mut, twiddle_stages, F, P};
    use crate::algebra::{FieldNTT, Ring};
    use core::arch::aarch64::*;

    /// Number of `u64` lanes per NEON register.
    const WIDTH: usize = 2;

    #[inline(always)]
    unsafe fn load(p: *const u64) -> uint64x2_t {
        vld1q_u64(p)
    }
    #[inline(always)]
    unsafe fn store(p: *mut u64, v: uint64x2_t) {
        vst1q_u64(p, v);
    }
    #[inline(always)]
    unsafe fn splat(x: u64) -> uint64x2_t {
        vdupq_n_u64(x)
    }
    /// Per-lane `mask ? t : f` (mask must be all-ones / all-zeros).
    #[inline(always)]
    unsafe fn select(mask: uint64x2_t, t: uint64x2_t, f: uint64x2_t) -> uint64x2_t {
        vbslq_u64(mask, t, f)
    }

    /// Field add; mirrors `F::add_inner`.
    #[inline(always)]
    unsafe fn add(x: uint64x2_t, y: uint64x2_t) -> uint64x2_t {
        let p = splat(P);
        let sum = vaddq_u64(x, y);
        let overflow = vcltq_u64(sum, x);
        let ge_p = vcgeq_u64(sum, p);
        let cond = vorrq_u64(overflow, ge_p);
        select(cond, vsubq_u64(sum, p), sum)
    }
    /// Field sub; mirrors `F::sub_inner`.
    #[inline(always)]
    unsafe fn sub(x: uint64x2_t, y: uint64x2_t) -> uint64x2_t {
        let p = splat(P);
        let diff = vsubq_u64(x, y);
        let borrow = vcltq_u64(x, y);
        select(borrow, vaddq_u64(diff, p), diff)
    }
    /// Widening `64 x 64 -> 128` per lane, returning `(lo, hi)`.
    #[inline(always)]
    unsafe fn mul_wide(a: uint64x2_t, b: uint64x2_t) -> (uint64x2_t, uint64x2_t) {
        let mask32 = vdupq_n_u64(0xFFFF_FFFF);
        let a_lo = vmovn_u64(a);
        let a_hi = vshrn_n_u64(a, 32);
        let b_lo = vmovn_u64(b);
        let b_hi = vshrn_n_u64(b, 32);
        // 32x32 -> 64 partial products.
        let ll = vmull_u32(a_lo, b_lo);
        let lh = vmull_u32(a_lo, b_hi);
        let hl = vmull_u32(a_hi, b_lo);
        let hh = vmull_u32(a_hi, b_hi);
        // Combine columns; each 64-bit add below is overflow-free for 32-bit inputs.
        let ll_hi = vshrq_n_u64(ll, 32);
        let t = vaddq_u64(lh, ll_hi);
        let t_lo = vandq_u64(t, mask32);
        let t_hi = vshrq_n_u64(t, 32);
        let u = vaddq_u64(hl, t_lo);
        let lo = vorrq_u64(vandq_u64(ll, mask32), vshlq_n_u64(vandq_u64(u, mask32), 32));
        let hi = vaddq_u64(vaddq_u64(hh, t_hi), vshrq_n_u64(u, 32));
        (lo, hi)
    }
    /// Field mul; mirrors `F::reduce_128(a*b)`.
    #[inline(always)]
    unsafe fn mul(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
        let (lo, hi) = mul_wide(a, b);
        let mask32 = vdupq_n_u64(0xFFFF_FFFF);
        let mid = vandq_u64(hi, mask32);
        let top = vshrq_n_u64(hi, 32);
        let beps = vsubq_u64(vshlq_n_u64(mid, 32), mid);
        add(sub(lo, top), beps)
    }
    /// Field halving; mirrors `F::div_2`.
    #[inline(always)]
    unsafe fn div2(x: uint64x2_t) -> uint64x2_t {
        let one = vdupq_n_u64(1);
        let odd = vceqq_u64(vandq_u64(x, one), one);
        let even = vshrq_n_u64(x, 1);
        let addp = vaddq_u64(x, splat(P));
        let carry = vcltq_u64(addp, x);
        let carry_hi = vandq_u64(carry, vdupq_n_u64(0x8000_0000_0000_0000));
        let odd_res = vorrq_u64(carry_hi, vshrq_n_u64(addp, 1));
        select(odd, odd_res, even)
    }

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn ntt_dense<const FORWARD: bool>(rows: usize, cols: usize, data: &mut [F]) {
        let lg_rows = crate::ntt::dense_ntt_lg_rows(rows, cols, data.len());
        let raw = as_u64_mut(data);
        let ptr = raw.as_mut_ptr();
        let main = cols - cols % WIDTH;
        for (stage, w_stage) in twiddle_stages::<FORWARD>(lg_rows) {
            let skip = 1usize << stage;
            let mut i = 0;
            while i < rows {
                let mut w_j = F::one();
                for j in 0..skip {
                    let base_a = (i + j) * cols;
                    let base_b = (i + j + skip) * cols;
                    let wv = splat(w_j.0);
                    let mut k = 0;
                    while k < main {
                        let pa = ptr.add(base_a + k);
                        let pb = ptr.add(base_b + k);
                        let a = load(pa);
                        let b = load(pb);
                        if FORWARD {
                            let t = mul(wv, b);
                            store(pa, add(a, t));
                            store(pb, sub(a, t));
                        } else {
                            let s = add(a, b);
                            let d = sub(a, b);
                            store(pa, div2(s));
                            store(pb, div2(mul(d, wv)));
                        }
                        k += WIDTH;
                    }
                    for k in main..cols {
                        let a = F(*ptr.add(base_a + k));
                        let b = F(*ptr.add(base_b + k));
                        if FORWARD {
                            let t = w_j * b;
                            *ptr.add(base_a + k) = (a + t).0;
                            *ptr.add(base_b + k) = (a - t).0;
                        } else {
                            *ptr.add(base_a + k) = (a + b).div_2().0;
                            *ptr.add(base_b + k) = ((a - b) * w_j).div_2().0;
                        }
                    }
                    w_j *= &w_stage;
                }
                i += 2 * skip;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{super::EPSILON, add, div2, mul, sub, F, P};
        use crate::algebra::FieldNTT;
        use core::arch::aarch64::*;

        fn lanes_of(
            op: unsafe fn(uint64x2_t, uint64x2_t) -> uint64x2_t,
            a: [u64; 2],
            b: [u64; 2],
        ) -> [u64; 2] {
            // SAFETY: NEON is part of the aarch64 baseline.
            unsafe {
                let va = vld1q_u64(a.as_ptr());
                let vb = vld1q_u64(b.as_ptr());
                let r = op(va, vb);
                let mut out = [0u64; 2];
                vst1q_u64(out.as_mut_ptr(), r);
                out
            }
        }

        unsafe fn div2_bin(x: uint64x2_t, _y: uint64x2_t) -> uint64x2_t {
            div2(x)
        }

        fn samples() -> Vec<u64> {
            let mut v = vec![
                0u64,
                1,
                2,
                P - 1,
                P - 2,
                EPSILON,
                EPSILON + 1,
                1 << 32,
                (1 << 32) - 1,
                1 << 63,
                u64::MAX % P,
                P / 2,
                12345678901234567 % P,
            ];
            let mut x = 0x1234_5678_9abc_def0u64;
            for _ in 0..200 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                v.push(x % P);
            }
            v
        }

        #[test]
        fn neon_field_ops_match_scalar() {
            let s = samples();
            for &a in &s {
                for &b in &s {
                    let aa = [a, b];
                    let bb = [b, (a + 3) % P];
                    let exp_add: [u64; 2] = core::array::from_fn(|i| (F(aa[i]) + F(bb[i])).0);
                    let exp_sub: [u64; 2] = core::array::from_fn(|i| (F(aa[i]) - F(bb[i])).0);
                    let exp_mul: [u64; 2] = core::array::from_fn(|i| (F(aa[i]) * F(bb[i])).0);
                    assert_eq!(lanes_of(add, aa, bb), exp_add);
                    assert_eq!(lanes_of(sub, aa, bb), exp_sub);
                    assert_eq!(lanes_of(mul, aa, bb), exp_mul);
                }
            }
        }

        #[test]
        fn neon_div2_matches_scalar() {
            let s = samples();
            for chunk in s.chunks(2) {
                let mut aa = [0u64; 2];
                aa[..chunk.len()].copy_from_slice(chunk);
                let exp: [u64; 2] = core::array::from_fn(|i| F(aa[i]).div_2().0);
                let got = lanes_of(div2_bin, aa, aa);
                assert_eq!(got, exp);
            }
        }
    }
}
