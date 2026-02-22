//! SIMD-accelerated GF(2^8) multiply-accumulate kernels.
//!
//! The core operation is `gf_vect_mad`: multiply a source byte slice by a GF(2^8)
//! constant and XOR-accumulate into a destination slice. This follows ISA-L's
//! approach with runtime SIMD tier detection and multi-destination variants for
//! cache efficiency.
//!
//! # SIMD Tiers
//!
//! 1. **GFNI+AVX2**: `_mm256_gf2p8mul_epi8` -- 32 GF multiplies per instruction
//! 2. **AVX2**: split-nibble via `_mm256_shuffle_epi8` -- 32 bytes per iteration
//! 3. **SSSE3**: split-nibble via `_mm_shuffle_epi8` -- 16 bytes per iteration
//! 4. **NEON** (AArch64): split-nibble via `vqtbl1q_u8` -- 16 bytes per iteration
//! 5. **Scalar**: log/exp table lookup -- 1 byte per iteration

use super::gf8_arithmetic::{init_mul_table, mul};
use std::sync::OnceLock;

// ======================================================================
// Public API
// ======================================================================

/// Multiply-accumulate: `dst[i] ^= gf_mul(coeff, src[i])` for all `i`.
///
/// Uses runtime SIMD detection to pick the fastest available implementation.
#[inline]
pub(crate) fn gf_vect_mad(dst: &mut [u8], src: &[u8], coeff: u8) {
    debug_assert_eq!(dst.len(), src.len());
    get_mad_fn()(dst, src, coeff);
}

/// Multi-destination multiply-accumulate (ISA-L-style optimization).
///
/// For each byte position: `dsts[d][i] ^= gf_mul(coeffs[d], src[i])` for all `d`.
///
/// This amortizes the cost of loading source data across multiple outputs,
/// dramatically improving cache utilization when computing multiple recovery shards.
#[inline]
pub(crate) fn gf_vect_mad_multi(dsts: &mut [&mut [u8]], src: &[u8], coeffs: &[u8]) {
    debug_assert_eq!(dsts.len(), coeffs.len());
    get_mad_multi_fn()(dsts, src, coeffs);
}

// ======================================================================
// Function pointer caching for runtime dispatch
// ======================================================================

type MadFn = fn(&mut [u8], &[u8], u8);
type MadMultiFn = fn(&mut [&mut [u8]], &[u8], &[u8]);

fn get_mad_fn() -> MadFn {
    static FN: OnceLock<MadFn> = OnceLock::new();
    *FN.get_or_init(detect_mad_fn)
}

fn get_mad_multi_fn() -> MadMultiFn {
    static FN: OnceLock<MadMultiFn> = OnceLock::new();
    *FN.get_or_init(detect_mad_multi_fn)
}

fn detect_mad_fn() -> MadFn {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if std::is_x86_feature_detected!("gfni") && std::is_x86_feature_detected!("avx2") {
            return |d, s, c| {
                // SAFETY: we checked for gfni+avx2 above
                unsafe { gfni_avx2::gf_vect_mad(d, s, c) }
            };
        }
        if std::is_x86_feature_detected!("avx2") {
            return |d, s, c| {
                // SAFETY: we checked for avx2 above
                unsafe { avx2::gf_vect_mad(d, s, c) }
            };
        }
        if std::is_x86_feature_detected!("ssse3") {
            return |d, s, c| {
                // SAFETY: we checked for ssse3 above
                unsafe { ssse3::gf_vect_mad(d, s, c) }
            };
        }
    }
    gf_vect_mad_scalar
}

fn detect_mad_multi_fn() -> MadMultiFn {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if std::is_x86_feature_detected!("gfni") && std::is_x86_feature_detected!("avx2") {
            return |d, s, c| {
                // SAFETY: we checked for gfni+avx2 above
                unsafe { gfni_avx2::gf_vect_mad_multi(d, s, c) }
            };
        }
        if std::is_x86_feature_detected!("avx2") {
            return |d, s, c| {
                // SAFETY: we checked for avx2 above
                unsafe { avx2::gf_vect_mad_multi(d, s, c) }
            };
        }
        if std::is_x86_feature_detected!("ssse3") {
            return |d, s, c| {
                // SAFETY: we checked for ssse3 above
                unsafe { ssse3::gf_vect_mad_multi(d, s, c) }
            };
        }
    }
    gf_vect_mad_multi_scalar
}

// ======================================================================
// Scalar fallback
// ======================================================================

fn gf_vect_mad_scalar(dst: &mut [u8], src: &[u8], coeff: u8) {
    if coeff == 0 {
        return;
    }
    if coeff == 1 {
        for (d, &s) in dst.iter_mut().zip(src.iter()) {
            *d ^= s;
        }
        return;
    }
    for (d, &s) in dst.iter_mut().zip(src.iter()) {
        *d ^= mul(coeff, s);
    }
}

fn gf_vect_mad_multi_scalar(dsts: &mut [&mut [u8]], src: &[u8], coeffs: &[u8]) {
    for (dst, &coeff) in dsts.iter_mut().zip(coeffs.iter()) {
        gf_vect_mad_scalar(dst, src, coeff);
    }
}

// ======================================================================
// x86/x86_64 SIMD implementations
// ======================================================================

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod avx2 {
    use super::*;

    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    /// Single-destination MAD using AVX2 split-nibble technique.
    ///
    /// # Safety
    /// Caller must ensure AVX2 is available.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn gf_vect_mad(dst: &mut [u8], src: &[u8], coeff: u8) {
        if coeff == 0 {
            return;
        }

        let (low_tbl, high_tbl) = init_mul_table(coeff);
        let low_v = _mm256_broadcastsi128_si256(_mm_loadu_si128(low_tbl.as_ptr().cast()));
        let high_v = _mm256_broadcastsi128_si256(_mm_loadu_si128(high_tbl.as_ptr().cast()));
        let mask = _mm256_set1_epi8(0x0F);

        let chunks = dst.len() / 32;

        for i in 0..chunks {
            let offset = i * 32;
            let s = _mm256_loadu_si256(src.as_ptr().add(offset).cast());
            let d = _mm256_loadu_si256(dst.as_ptr().add(offset).cast());

            let lo = _mm256_and_si256(s, mask);
            let hi = _mm256_and_si256(_mm256_srli_epi64::<4>(s), mask);

            let prod = _mm256_xor_si256(
                _mm256_shuffle_epi8(low_v, lo),
                _mm256_shuffle_epi8(high_v, hi),
            );

            _mm256_storeu_si256(
                dst.as_mut_ptr().add(offset).cast(),
                _mm256_xor_si256(d, prod),
            );
        }

        let tail_start = chunks * 32;
        gf_vect_mad_scalar(&mut dst[tail_start..], &src[tail_start..], coeff);
    }

    /// Multi-destination MAD using AVX2 split-nibble technique.
    ///
    /// Loads source data once per chunk and scatters multiply-accumulate results
    /// to multiple destinations, improving cache utilization.
    ///
    /// # Safety
    /// Caller must ensure AVX2 is available.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn gf_vect_mad_multi(
        dsts: &mut [&mut [u8]],
        src: &[u8],
        coeffs: &[u8],
    ) {
        let mask = _mm256_set1_epi8(0x0F);

        // Precompute lookup tables for all coefficients
        let tables: Vec<(__m256i, __m256i, bool)> = coeffs
            .iter()
            .map(|&c| {
                if c == 0 {
                    let z = _mm256_setzero_si256();
                    (z, z, true)
                } else {
                    let (lo, hi) = init_mul_table(c);
                    (
                        _mm256_broadcastsi128_si256(_mm_loadu_si128(lo.as_ptr().cast())),
                        _mm256_broadcastsi128_si256(_mm_loadu_si128(hi.as_ptr().cast())),
                        false,
                    )
                }
            })
            .collect();

        let chunks = src.len() / 32;

        for i in 0..chunks {
            let offset = i * 32;
            let s = _mm256_loadu_si256(src.as_ptr().add(offset).cast());
            let lo = _mm256_and_si256(s, mask);
            let hi = _mm256_and_si256(_mm256_srli_epi64::<4>(s), mask);

            for (d, &(lo_tbl, hi_tbl, is_zero)) in dsts.iter_mut().zip(tables.iter()) {
                if is_zero {
                    continue;
                }
                let d_ptr = d.as_mut_ptr().add(offset).cast::<__m256i>();
                let existing = _mm256_loadu_si256(d_ptr);
                let prod = _mm256_xor_si256(
                    _mm256_shuffle_epi8(lo_tbl, lo),
                    _mm256_shuffle_epi8(hi_tbl, hi),
                );
                _mm256_storeu_si256(d_ptr, _mm256_xor_si256(existing, prod));
            }
        }

        let tail = chunks * 32;
        for (dst, &coeff) in dsts.iter_mut().zip(coeffs.iter()) {
            gf_vect_mad_scalar(&mut dst[tail..], &src[tail..], coeff);
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod gfni_avx2 {
    use super::*;

    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    /// Single-destination MAD using GFNI+AVX2.
    ///
    /// # Safety
    /// Caller must ensure AVX2 and GFNI are available.
    #[target_feature(enable = "avx2,gfni")]
    pub(super) unsafe fn gf_vect_mad(dst: &mut [u8], src: &[u8], coeff: u8) {
        if coeff == 0 {
            return;
        }

        let coeff_v = _mm256_set1_epi8(coeff as i8);
        let chunks = dst.len() / 32;

        for i in 0..chunks {
            let offset = i * 32;
            let s = _mm256_loadu_si256(src.as_ptr().add(offset).cast());
            let d = _mm256_loadu_si256(dst.as_ptr().add(offset).cast());
            let prod = _mm256_gf2p8mul_epi8(coeff_v, s);
            _mm256_storeu_si256(
                dst.as_mut_ptr().add(offset).cast(),
                _mm256_xor_si256(d, prod),
            );
        }

        let tail_start = chunks * 32;
        gf_vect_mad_scalar(&mut dst[tail_start..], &src[tail_start..], coeff);
    }

    /// Multi-destination MAD using GFNI+AVX2.
    ///
    /// # Safety
    /// Caller must ensure AVX2 and GFNI are available.
    #[target_feature(enable = "avx2,gfni")]
    pub(super) unsafe fn gf_vect_mad_multi(
        dsts: &mut [&mut [u8]],
        src: &[u8],
        coeffs: &[u8],
    ) {
        let coeff_vs: Vec<(__m256i, bool)> = coeffs
            .iter()
            .map(|&c| {
                if c == 0 {
                    (_mm256_setzero_si256(), true)
                } else {
                    (_mm256_set1_epi8(c as i8), false)
                }
            })
            .collect();

        let chunks = src.len() / 32;

        for i in 0..chunks {
            let offset = i * 32;
            let s = _mm256_loadu_si256(src.as_ptr().add(offset).cast());

            for (d, &(cv, is_zero)) in dsts.iter_mut().zip(coeff_vs.iter()) {
                if is_zero {
                    continue;
                }
                let d_ptr = d.as_mut_ptr().add(offset).cast::<__m256i>();
                let existing = _mm256_loadu_si256(d_ptr);
                let prod = _mm256_gf2p8mul_epi8(cv, s);
                _mm256_storeu_si256(d_ptr, _mm256_xor_si256(existing, prod));
            }
        }

        let tail = chunks * 32;
        for (dst, &coeff) in dsts.iter_mut().zip(coeffs.iter()) {
            gf_vect_mad_scalar(&mut dst[tail..], &src[tail..], coeff);
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod ssse3 {
    use super::*;

    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    /// Single-destination MAD using SSSE3 split-nibble technique.
    ///
    /// # Safety
    /// Caller must ensure SSSE3 is available.
    #[target_feature(enable = "ssse3")]
    pub(super) unsafe fn gf_vect_mad(dst: &mut [u8], src: &[u8], coeff: u8) {
        if coeff == 0 {
            return;
        }

        let (low_tbl, high_tbl) = init_mul_table(coeff);
        let low_v = _mm_loadu_si128(low_tbl.as_ptr().cast());
        let high_v = _mm_loadu_si128(high_tbl.as_ptr().cast());
        let mask = _mm_set1_epi8(0x0F);

        let chunks = dst.len() / 16;

        for i in 0..chunks {
            let offset = i * 16;
            let s = _mm_loadu_si128(src.as_ptr().add(offset).cast());
            let d = _mm_loadu_si128(dst.as_ptr().add(offset).cast());

            let lo = _mm_and_si128(s, mask);
            let hi = _mm_and_si128(_mm_srli_epi64::<4>(s), mask);

            let prod = _mm_xor_si128(_mm_shuffle_epi8(low_v, lo), _mm_shuffle_epi8(high_v, hi));

            _mm_storeu_si128(
                dst.as_mut_ptr().add(offset).cast(),
                _mm_xor_si128(d, prod),
            );
        }

        let tail_start = chunks * 16;
        gf_vect_mad_scalar(&mut dst[tail_start..], &src[tail_start..], coeff);
    }

    /// Multi-destination MAD using SSSE3 split-nibble technique.
    ///
    /// # Safety
    /// Caller must ensure SSSE3 is available.
    #[target_feature(enable = "ssse3")]
    pub(super) unsafe fn gf_vect_mad_multi(
        dsts: &mut [&mut [u8]],
        src: &[u8],
        coeffs: &[u8],
    ) {
        let mask = _mm_set1_epi8(0x0F);

        let tables: Vec<(__m128i, __m128i, bool)> = coeffs
            .iter()
            .map(|&c| {
                if c == 0 {
                    let z = _mm_setzero_si128();
                    (z, z, true)
                } else {
                    let (lo, hi) = init_mul_table(c);
                    (
                        _mm_loadu_si128(lo.as_ptr().cast()),
                        _mm_loadu_si128(hi.as_ptr().cast()),
                        false,
                    )
                }
            })
            .collect();

        let chunks = src.len() / 16;

        for i in 0..chunks {
            let offset = i * 16;
            let s = _mm_loadu_si128(src.as_ptr().add(offset).cast());
            let lo = _mm_and_si128(s, mask);
            let hi = _mm_and_si128(_mm_srli_epi64::<4>(s), mask);

            for (d, &(lo_tbl, hi_tbl, is_zero)) in dsts.iter_mut().zip(tables.iter()) {
                if is_zero {
                    continue;
                }
                let d_ptr = d.as_mut_ptr().add(offset).cast::<__m128i>();
                let existing = _mm_loadu_si128(d_ptr);
                let prod =
                    _mm_xor_si128(_mm_shuffle_epi8(lo_tbl, lo), _mm_shuffle_epi8(hi_tbl, hi));
                _mm_storeu_si128(d_ptr, _mm_xor_si128(existing, prod));
            }
        }

        let tail = chunks * 16;
        for (dst, &coeff) in dsts.iter_mut().zip(coeffs.iter()) {
            gf_vect_mad_scalar(&mut dst[tail..], &src[tail..], coeff);
        }
    }
}

// ======================================================================
// AArch64 NEON implementation
// ======================================================================

#[cfg(target_arch = "aarch64")]
mod neon {
    use super::*;
    use core::arch::aarch64::*;

    /// Single-destination MAD using NEON split-nibble technique.
    pub(super) fn gf_vect_mad(dst: &mut [u8], src: &[u8], coeff: u8) {
        if coeff == 0 {
            return;
        }

        let (low_tbl, high_tbl) = init_mul_table(coeff);
        // SAFETY: NEON is baseline on AArch64
        let low_v: uint8x16_t = unsafe { vld1q_u8(low_tbl.as_ptr()) };
        let high_v: uint8x16_t = unsafe { vld1q_u8(high_tbl.as_ptr()) };
        let mask: uint8x16_t = unsafe { vdupq_n_u8(0x0F) };

        let chunks = dst.len() / 16;
        for i in 0..chunks {
            unsafe {
                let offset = i * 16;
                let s = vld1q_u8(src.as_ptr().add(offset));
                let d = vld1q_u8(dst.as_ptr().add(offset));

                let lo = vandq_u8(s, mask);
                let hi = vandq_u8(vshrq_n_u8::<4>(s), mask);

                let prod = veorq_u8(vqtbl1q_u8(low_v, lo), vqtbl1q_u8(high_v, hi));
                vst1q_u8(dst.as_mut_ptr().add(offset), veorq_u8(d, prod));
            }
        }

        let tail_start = chunks * 16;
        gf_vect_mad_scalar(&mut dst[tail_start..], &src[tail_start..], coeff);
    }

    /// Multi-destination MAD using NEON split-nibble technique.
    pub(super) fn gf_vect_mad_multi(
        dsts: &mut [&mut [u8]],
        src: &[u8],
        coeffs: &[u8],
    ) {
        let mask: uint8x16_t = unsafe { vdupq_n_u8(0x0F) };

        let tables: Vec<(uint8x16_t, uint8x16_t, bool)> = coeffs
            .iter()
            .map(|&c| {
                if c == 0 {
                    unsafe {
                        let z = vdupq_n_u8(0);
                        (z, z, true)
                    }
                } else {
                    let (lo, hi) = init_mul_table(c);
                    unsafe { (vld1q_u8(lo.as_ptr()), vld1q_u8(hi.as_ptr()), false) }
                }
            })
            .collect();

        let chunks = src.len() / 16;
        for i in 0..chunks {
            unsafe {
                let offset = i * 16;
                let s = vld1q_u8(src.as_ptr().add(offset));
                let lo = vandq_u8(s, mask);
                let hi = vandq_u8(vshrq_n_u8::<4>(s), mask);

                for (d, &(lo_tbl, hi_tbl, is_zero)) in dsts.iter_mut().zip(tables.iter()) {
                    if is_zero {
                        continue;
                    }
                    let existing = vld1q_u8(d.as_ptr().add(offset));
                    let prod = veorq_u8(vqtbl1q_u8(lo_tbl, lo), vqtbl1q_u8(hi_tbl, hi));
                    vst1q_u8(d.as_mut_ptr().add(offset), veorq_u8(existing, prod));
                }
            }
        }

        let tail = chunks * 16;
        for (dst, &coeff) in dsts.iter_mut().zip(coeffs.iter()) {
            gf_vect_mad_scalar(&mut dst[tail..], &src[tail..], coeff);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference scalar implementation for cross-validation.
    fn reference_mad(dst: &mut [u8], src: &[u8], coeff: u8) {
        for (d, &s) in dst.iter_mut().zip(src.iter()) {
            *d ^= mul(coeff, s);
        }
    }

    #[test]
    fn test_scalar_matches_reference() {
        let src = (0..=255).collect::<Vec<u8>>();
        for c in [0u8, 1, 2, 127, 128, 255] {
            let mut dst_ref = vec![0u8; 256];
            let mut dst_scalar = vec![0u8; 256];
            reference_mad(&mut dst_ref, &src, c);
            gf_vect_mad_scalar(&mut dst_scalar, &src, c);
            assert_eq!(dst_ref, dst_scalar, "scalar mismatch for coeff={c}");
        }
    }

    #[test]
    fn test_dispatched_matches_scalar() {
        for len in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 127, 128, 1024, 4096] {
            let src: Vec<u8> = (0..len).map(|i| (i * 37 + 13) as u8).collect();
            for c in [0u8, 1, 2, 42, 127, 128, 200, 255] {
                let mut dst_ref = vec![0x55u8; len];
                let mut dst_test = vec![0x55u8; len];
                reference_mad(&mut dst_ref, &src, c);
                gf_vect_mad(&mut dst_test, &src, c);
                assert_eq!(
                    dst_ref, dst_test,
                    "dispatch mismatch at len={len}, coeff={c}"
                );
            }
        }
    }

    #[test]
    fn test_multi_matches_sequential() {
        for len in [0, 1, 31, 32, 33, 128, 1024] {
            let src: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let coeffs = [3u8, 0, 127, 255, 1];
            let n = coeffs.len();

            // Sequential single-destination
            let mut dsts_seq: Vec<Vec<u8>> = (0..n).map(|_| vec![0xAAu8; len]).collect();
            for (d, &c) in dsts_seq.iter_mut().zip(coeffs.iter()) {
                gf_vect_mad(d, &src, c);
            }

            // Multi-destination
            let mut dsts_multi: Vec<Vec<u8>> = (0..n).map(|_| vec![0xAAu8; len]).collect();
            let mut refs: Vec<&mut [u8]> =
                dsts_multi.iter_mut().map(|v| v.as_mut_slice()).collect();
            gf_vect_mad_multi(&mut refs, &src, &coeffs);

            for d in 0..n {
                assert_eq!(
                    dsts_seq[d], dsts_multi[d],
                    "multi mismatch at len={len}, dst={d}"
                );
            }
        }
    }

    #[test]
    fn test_all_coefficients() {
        let len = 256;
        let src: Vec<u8> = (0..len).map(|i| i as u8).collect();
        for c in 0..=255u8 {
            let mut dst_ref = vec![0u8; len];
            let mut dst_test = vec![0u8; len];
            reference_mad(&mut dst_ref, &src, c);
            gf_vect_mad(&mut dst_test, &src, c);
            assert_eq!(dst_ref, dst_test, "mismatch for coeff={c}");
        }
    }

    #[test]
    fn test_accumulation() {
        // Verify that MAD accumulates (XORs) rather than overwrites
        let src = vec![0xFFu8; 64];
        let mut dst = vec![0xAAu8; 64];
        gf_vect_mad(&mut dst, &src, 1);
        // dst[i] = 0xAA ^ (1 * 0xFF) = 0xAA ^ 0xFF = 0x55
        assert!(dst.iter().all(|&b| b == 0x55), "accumulation failed");
    }

    #[test]
    fn test_large_data() {
        // ~127KB, similar to production shard size
        let len = 127 * 1024;
        let src: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let mut dst_ref = vec![0u8; len];
        let mut dst_test = vec![0u8; len];
        reference_mad(&mut dst_ref, &src, 0x53);
        gf_vect_mad(&mut dst_test, &src, 0x53);
        assert_eq!(dst_ref, dst_test, "large data mismatch");
    }
}
