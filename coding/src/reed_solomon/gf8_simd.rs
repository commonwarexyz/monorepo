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
/// All coefficients must be nonzero. The caller is responsible for filtering
/// out zero coefficients before calling this function.
///
/// This amortizes the cost of loading source data across multiple outputs,
/// dramatically improving cache utilization when computing multiple recovery shards.
#[inline]
#[cfg(test)]
pub(crate) fn gf_vect_mad_multi(dsts: &mut [&mut [u8]], src: &[u8], coeffs: &[u8]) {
    debug_assert_eq!(dsts.len(), coeffs.len());
    debug_assert!(coeffs.iter().all(|&c| c != 0));
    get_mad_multi_fn()(dsts, src, coeffs);
}

/// Raw-pointer multi-destination MAD for zero-allocation hot paths.
///
/// # Safety
///
/// - Each `dsts[i]` must point to a valid, writable buffer of at least `len` bytes.
/// - All destination buffers must be non-overlapping.
/// - All coefficients must be nonzero.
#[inline]
pub(crate) unsafe fn gf_vect_mad_multi_raw(
    dsts: &[*mut u8],
    src: &[u8],
    coeffs: &[u8],
    len: usize,
) {
    debug_assert_eq!(dsts.len(), coeffs.len());
    // Convert raw pointers to slices and delegate to the dispatched function.
    // The slice construction is zero-cost (just pointer + length).
    // We use a fixed-size stack buffer to avoid heap allocation.
    const MAX_DSTS: usize = 255;
    debug_assert!(dsts.len() <= MAX_DSTS);
    let n = dsts.len();

    // Build &mut [u8] slices from raw pointers on the stack using MaybeUninit
    // to avoid needing Copy/Default for &mut [u8].
    let mut slices: [std::mem::MaybeUninit<&mut [u8]>; MAX_DSTS] =
        [const { std::mem::MaybeUninit::uninit() }; MAX_DSTS];
    for i in 0..n {
        slices[i].write(std::slice::from_raw_parts_mut(dsts[i], len));
    }

    // SAFETY: first `n` elements are initialized above
    let slice_refs: &mut [&mut [u8]] = std::slice::from_raw_parts_mut(
        slices.as_mut_ptr().cast::<&mut [u8]>(),
        n,
    );

    get_mad_multi_fn()(slice_refs, src, coeffs);
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

        let len = dst.len();
        let chunks = len / 64;

        // Process 64 bytes (2x __m256i) per iteration
        for i in 0..chunks {
            let offset = i * 64;
            let s0 = _mm256_loadu_si256(src.as_ptr().add(offset).cast());
            let s1 = _mm256_loadu_si256(src.as_ptr().add(offset + 32).cast());
            let d0 = _mm256_loadu_si256(dst.as_ptr().add(offset).cast());
            let d1 = _mm256_loadu_si256(dst.as_ptr().add(offset + 32).cast());

            let lo0 = _mm256_and_si256(s0, mask);
            let hi0 = _mm256_and_si256(_mm256_srli_epi64::<4>(s0), mask);
            let p0 = _mm256_xor_si256(
                _mm256_shuffle_epi8(low_v, lo0),
                _mm256_shuffle_epi8(high_v, hi0),
            );

            let lo1 = _mm256_and_si256(s1, mask);
            let hi1 = _mm256_and_si256(_mm256_srli_epi64::<4>(s1), mask);
            let p1 = _mm256_xor_si256(
                _mm256_shuffle_epi8(low_v, lo1),
                _mm256_shuffle_epi8(high_v, hi1),
            );

            _mm256_storeu_si256(
                dst.as_mut_ptr().add(offset).cast(),
                _mm256_xor_si256(d0, p0),
            );
            _mm256_storeu_si256(
                dst.as_mut_ptr().add(offset + 32).cast(),
                _mm256_xor_si256(d1, p1),
            );
        }

        // Handle remaining 32-byte chunk
        let tail_start = chunks * 64;
        if tail_start + 32 <= len {
            let s = _mm256_loadu_si256(src.as_ptr().add(tail_start).cast());
            let d = _mm256_loadu_si256(dst.as_ptr().add(tail_start).cast());
            let lo = _mm256_and_si256(s, mask);
            let hi = _mm256_and_si256(_mm256_srli_epi64::<4>(s), mask);
            let p = _mm256_xor_si256(
                _mm256_shuffle_epi8(low_v, lo),
                _mm256_shuffle_epi8(high_v, hi),
            );
            _mm256_storeu_si256(
                dst.as_mut_ptr().add(tail_start).cast(),
                _mm256_xor_si256(d, p),
            );
            gf_vect_mad_scalar(&mut dst[tail_start + 32..], &src[tail_start + 32..], coeff);
        } else {
            gf_vect_mad_scalar(&mut dst[tail_start..], &src[tail_start..], coeff);
        }
    }

    /// Multi-destination MAD using AVX2 split-nibble technique.
    ///
    /// All coefficients must be nonzero. No internal heap allocation.
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
        let ndst = dsts.len();

        // Precompute lookup tables on the stack (max 255 destinations)
        let mut lo_tbls = [_mm256_setzero_si256(); 255];
        let mut hi_tbls = [_mm256_setzero_si256(); 255];
        for i in 0..ndst {
            let (lo, hi) = init_mul_table(coeffs[i]);
            lo_tbls[i] = _mm256_broadcastsi128_si256(_mm_loadu_si128(lo.as_ptr().cast()));
            hi_tbls[i] = _mm256_broadcastsi128_si256(_mm_loadu_si128(hi.as_ptr().cast()));
        }

        let len = src.len();
        let chunks = len / 64;

        // Process 64 bytes per iteration (2x __m256i), unrolled
        for i in 0..chunks {
            let offset = i * 64;
            let s0 = _mm256_loadu_si256(src.as_ptr().add(offset).cast());
            let s1 = _mm256_loadu_si256(src.as_ptr().add(offset + 32).cast());
            let lo0 = _mm256_and_si256(s0, mask);
            let hi0 = _mm256_and_si256(_mm256_srli_epi64::<4>(s0), mask);
            let lo1 = _mm256_and_si256(s1, mask);
            let hi1 = _mm256_and_si256(_mm256_srli_epi64::<4>(s1), mask);

            for d in 0..ndst {
                let d_ptr0 = dsts[d].as_mut_ptr().add(offset).cast::<__m256i>();
                let d_ptr1 = dsts[d].as_mut_ptr().add(offset + 32).cast::<__m256i>();

                let p0 = _mm256_xor_si256(
                    _mm256_shuffle_epi8(lo_tbls[d], lo0),
                    _mm256_shuffle_epi8(hi_tbls[d], hi0),
                );
                let p1 = _mm256_xor_si256(
                    _mm256_shuffle_epi8(lo_tbls[d], lo1),
                    _mm256_shuffle_epi8(hi_tbls[d], hi1),
                );

                _mm256_storeu_si256(d_ptr0, _mm256_xor_si256(_mm256_loadu_si256(d_ptr0), p0));
                _mm256_storeu_si256(d_ptr1, _mm256_xor_si256(_mm256_loadu_si256(d_ptr1), p1));
            }
        }

        // Tail: remaining 32-byte chunk
        let tail_start = chunks * 64;
        if tail_start + 32 <= len {
            let s = _mm256_loadu_si256(src.as_ptr().add(tail_start).cast());
            let lo = _mm256_and_si256(s, mask);
            let hi = _mm256_and_si256(_mm256_srli_epi64::<4>(s), mask);

            for d in 0..ndst {
                let d_ptr = dsts[d].as_mut_ptr().add(tail_start).cast::<__m256i>();
                let p = _mm256_xor_si256(
                    _mm256_shuffle_epi8(lo_tbls[d], lo),
                    _mm256_shuffle_epi8(hi_tbls[d], hi),
                );
                _mm256_storeu_si256(d_ptr, _mm256_xor_si256(_mm256_loadu_si256(d_ptr), p));
            }
            for (d, &coeff) in dsts.iter_mut().zip(coeffs.iter()) {
                gf_vect_mad_scalar(&mut d[tail_start + 32..], &src[tail_start + 32..], coeff);
            }
        } else {
            for (d, &coeff) in dsts.iter_mut().zip(coeffs.iter()) {
                gf_vect_mad_scalar(&mut d[tail_start..], &src[tail_start..], coeff);
            }
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
        let len = dst.len();
        let chunks = len / 64;

        // Process 64 bytes per iteration (2x __m256i)
        for i in 0..chunks {
            let offset = i * 64;
            let s0 = _mm256_loadu_si256(src.as_ptr().add(offset).cast());
            let s1 = _mm256_loadu_si256(src.as_ptr().add(offset + 32).cast());
            let d0 = _mm256_loadu_si256(dst.as_ptr().add(offset).cast());
            let d1 = _mm256_loadu_si256(dst.as_ptr().add(offset + 32).cast());

            let p0 = _mm256_gf2p8mul_epi8(coeff_v, s0);
            let p1 = _mm256_gf2p8mul_epi8(coeff_v, s1);

            _mm256_storeu_si256(
                dst.as_mut_ptr().add(offset).cast(),
                _mm256_xor_si256(d0, p0),
            );
            _mm256_storeu_si256(
                dst.as_mut_ptr().add(offset + 32).cast(),
                _mm256_xor_si256(d1, p1),
            );
        }

        let tail_start = chunks * 64;
        if tail_start + 32 <= len {
            let s = _mm256_loadu_si256(src.as_ptr().add(tail_start).cast());
            let d = _mm256_loadu_si256(dst.as_ptr().add(tail_start).cast());
            let p = _mm256_gf2p8mul_epi8(coeff_v, s);
            _mm256_storeu_si256(
                dst.as_mut_ptr().add(tail_start).cast(),
                _mm256_xor_si256(d, p),
            );
            gf_vect_mad_scalar(&mut dst[tail_start + 32..], &src[tail_start + 32..], coeff);
        } else {
            gf_vect_mad_scalar(&mut dst[tail_start..], &src[tail_start..], coeff);
        }
    }

    /// Multi-destination MAD using GFNI+AVX2.
    ///
    /// All coefficients must be nonzero. No internal heap allocation.
    ///
    /// # Safety
    /// Caller must ensure AVX2 and GFNI are available.
    #[target_feature(enable = "avx2,gfni")]
    pub(super) unsafe fn gf_vect_mad_multi(
        dsts: &mut [&mut [u8]],
        src: &[u8],
        coeffs: &[u8],
    ) {
        let ndst = dsts.len();

        // Precompute broadcast coefficients on the stack
        let mut coeff_vs = [_mm256_setzero_si256(); 255];
        for i in 0..ndst {
            coeff_vs[i] = _mm256_set1_epi8(coeffs[i] as i8);
        }

        let len = src.len();
        let chunks = len / 64;

        // Process 64 bytes per iteration (2x __m256i), unrolled
        for i in 0..chunks {
            let offset = i * 64;
            let s0 = _mm256_loadu_si256(src.as_ptr().add(offset).cast());
            let s1 = _mm256_loadu_si256(src.as_ptr().add(offset + 32).cast());

            for d in 0..ndst {
                let d_ptr0 = dsts[d].as_mut_ptr().add(offset).cast::<__m256i>();
                let d_ptr1 = dsts[d].as_mut_ptr().add(offset + 32).cast::<__m256i>();

                let p0 = _mm256_gf2p8mul_epi8(coeff_vs[d], s0);
                let p1 = _mm256_gf2p8mul_epi8(coeff_vs[d], s1);

                _mm256_storeu_si256(d_ptr0, _mm256_xor_si256(_mm256_loadu_si256(d_ptr0), p0));
                _mm256_storeu_si256(d_ptr1, _mm256_xor_si256(_mm256_loadu_si256(d_ptr1), p1));
            }
        }

        // Tail
        let tail_start = chunks * 64;
        if tail_start + 32 <= len {
            let s = _mm256_loadu_si256(src.as_ptr().add(tail_start).cast());
            for d in 0..ndst {
                let d_ptr = dsts[d].as_mut_ptr().add(tail_start).cast::<__m256i>();
                let p = _mm256_gf2p8mul_epi8(coeff_vs[d], s);
                _mm256_storeu_si256(d_ptr, _mm256_xor_si256(_mm256_loadu_si256(d_ptr), p));
            }
            for (d, &coeff) in dsts.iter_mut().zip(coeffs.iter()) {
                gf_vect_mad_scalar(&mut d[tail_start + 32..], &src[tail_start + 32..], coeff);
            }
        } else {
            for (d, &coeff) in dsts.iter_mut().zip(coeffs.iter()) {
                gf_vect_mad_scalar(&mut d[tail_start..], &src[tail_start..], coeff);
            }
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

        let len = dst.len();
        let chunks = len / 32;

        // Process 32 bytes (2x __m128i) per iteration
        for i in 0..chunks {
            let offset = i * 32;
            let s0 = _mm_loadu_si128(src.as_ptr().add(offset).cast());
            let s1 = _mm_loadu_si128(src.as_ptr().add(offset + 16).cast());
            let d0 = _mm_loadu_si128(dst.as_ptr().add(offset).cast());
            let d1 = _mm_loadu_si128(dst.as_ptr().add(offset + 16).cast());

            let p0 = _mm_xor_si128(
                _mm_shuffle_epi8(low_v, _mm_and_si128(s0, mask)),
                _mm_shuffle_epi8(high_v, _mm_and_si128(_mm_srli_epi64::<4>(s0), mask)),
            );
            let p1 = _mm_xor_si128(
                _mm_shuffle_epi8(low_v, _mm_and_si128(s1, mask)),
                _mm_shuffle_epi8(high_v, _mm_and_si128(_mm_srli_epi64::<4>(s1), mask)),
            );

            _mm_storeu_si128(
                dst.as_mut_ptr().add(offset).cast(),
                _mm_xor_si128(d0, p0),
            );
            _mm_storeu_si128(
                dst.as_mut_ptr().add(offset + 16).cast(),
                _mm_xor_si128(d1, p1),
            );
        }

        let tail_start = chunks * 32;
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
        let ndst = dsts.len();

        // Stack-allocated lookup tables
        let mut lo_tbls = [_mm_setzero_si128(); 255];
        let mut hi_tbls = [_mm_setzero_si128(); 255];
        for i in 0..ndst {
            let (lo, hi) = init_mul_table(coeffs[i]);
            lo_tbls[i] = _mm_loadu_si128(lo.as_ptr().cast());
            hi_tbls[i] = _mm_loadu_si128(hi.as_ptr().cast());
        }

        let len = src.len();
        let chunks = len / 32;

        for i in 0..chunks {
            let offset = i * 32;
            let s0 = _mm_loadu_si128(src.as_ptr().add(offset).cast());
            let s1 = _mm_loadu_si128(src.as_ptr().add(offset + 16).cast());
            let lo0 = _mm_and_si128(s0, mask);
            let hi0 = _mm_and_si128(_mm_srli_epi64::<4>(s0), mask);
            let lo1 = _mm_and_si128(s1, mask);
            let hi1 = _mm_and_si128(_mm_srli_epi64::<4>(s1), mask);

            for d in 0..ndst {
                let d_ptr0 = dsts[d].as_mut_ptr().add(offset).cast::<__m128i>();
                let d_ptr1 = dsts[d].as_mut_ptr().add(offset + 16).cast::<__m128i>();

                let p0 = _mm_xor_si128(
                    _mm_shuffle_epi8(lo_tbls[d], lo0),
                    _mm_shuffle_epi8(hi_tbls[d], hi0),
                );
                let p1 = _mm_xor_si128(
                    _mm_shuffle_epi8(lo_tbls[d], lo1),
                    _mm_shuffle_epi8(hi_tbls[d], hi1),
                );

                _mm_storeu_si128(d_ptr0, _mm_xor_si128(_mm_loadu_si128(d_ptr0), p0));
                _mm_storeu_si128(d_ptr1, _mm_xor_si128(_mm_loadu_si128(d_ptr1), p1));
            }
        }

        let tail = chunks * 32;
        for (d, &coeff) in dsts.iter_mut().zip(coeffs.iter()) {
            gf_vect_mad_scalar(&mut d[tail..], &src[tail..], coeff);
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

        let len = dst.len();
        let chunks = len / 32;
        for i in 0..chunks {
            unsafe {
                let offset = i * 32;
                let s0 = vld1q_u8(src.as_ptr().add(offset));
                let s1 = vld1q_u8(src.as_ptr().add(offset + 16));
                let d0 = vld1q_u8(dst.as_ptr().add(offset));
                let d1 = vld1q_u8(dst.as_ptr().add(offset + 16));

                let p0 = veorq_u8(
                    vqtbl1q_u8(low_v, vandq_u8(s0, mask)),
                    vqtbl1q_u8(high_v, vandq_u8(vshrq_n_u8::<4>(s0), mask)),
                );
                let p1 = veorq_u8(
                    vqtbl1q_u8(low_v, vandq_u8(s1, mask)),
                    vqtbl1q_u8(high_v, vandq_u8(vshrq_n_u8::<4>(s1), mask)),
                );

                vst1q_u8(dst.as_mut_ptr().add(offset), veorq_u8(d0, p0));
                vst1q_u8(dst.as_mut_ptr().add(offset + 16), veorq_u8(d1, p1));
            }
        }

        let tail_start = chunks * 32;
        gf_vect_mad_scalar(&mut dst[tail_start..], &src[tail_start..], coeff);
    }

    /// Multi-destination MAD using NEON split-nibble technique.
    pub(super) fn gf_vect_mad_multi(
        dsts: &mut [&mut [u8]],
        src: &[u8],
        coeffs: &[u8],
    ) {
        let mask: uint8x16_t = unsafe { vdupq_n_u8(0x0F) };
        let ndst = dsts.len();

        let mut lo_tbls = [unsafe { vdupq_n_u8(0) }; 255];
        let mut hi_tbls = [unsafe { vdupq_n_u8(0) }; 255];
        for i in 0..ndst {
            let (lo, hi) = init_mul_table(coeffs[i]);
            lo_tbls[i] = unsafe { vld1q_u8(lo.as_ptr()) };
            hi_tbls[i] = unsafe { vld1q_u8(hi.as_ptr()) };
        }

        let len = src.len();
        let chunks = len / 32;
        for i in 0..chunks {
            unsafe {
                let offset = i * 32;
                let s0 = vld1q_u8(src.as_ptr().add(offset));
                let s1 = vld1q_u8(src.as_ptr().add(offset + 16));
                let lo0 = vandq_u8(s0, mask);
                let hi0 = vandq_u8(vshrq_n_u8::<4>(s0), mask);
                let lo1 = vandq_u8(s1, mask);
                let hi1 = vandq_u8(vshrq_n_u8::<4>(s1), mask);

                for d in 0..ndst {
                    let p0 =
                        veorq_u8(vqtbl1q_u8(lo_tbls[d], lo0), vqtbl1q_u8(hi_tbls[d], hi0));
                    let p1 =
                        veorq_u8(vqtbl1q_u8(lo_tbls[d], lo1), vqtbl1q_u8(hi_tbls[d], hi1));

                    let e0 = vld1q_u8(dsts[d].as_ptr().add(offset));
                    let e1 = vld1q_u8(dsts[d].as_ptr().add(offset + 16));
                    vst1q_u8(dsts[d].as_mut_ptr().add(offset), veorq_u8(e0, p0));
                    vst1q_u8(dsts[d].as_mut_ptr().add(offset + 16), veorq_u8(e1, p1));
                }
            }
        }

        let tail = chunks * 32;
        for (d, &coeff) in dsts.iter_mut().zip(coeffs.iter()) {
            gf_vect_mad_scalar(&mut d[tail..], &src[tail..], coeff);
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
        for len in [0, 1, 31, 32, 33, 63, 64, 128, 1024] {
            let src: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let coeffs = [3u8, 127, 255, 1, 42];
            let n = coeffs.len();

            // Sequential single-destination
            let mut dsts_seq: Vec<Vec<u8>> = (0..n).map(|_| vec![0xAAu8; len]).collect();
            for (d, &c) in dsts_seq.iter_mut().zip(coeffs.iter()) {
                gf_vect_mad(d, &src, c);
            }

            // Multi-destination (all coeffs nonzero as required)
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
        let src = vec![0xFFu8; 64];
        let mut dst = vec![0xAAu8; 64];
        gf_vect_mad(&mut dst, &src, 1);
        assert!(dst.iter().all(|&b| b == 0x55), "accumulation failed");
    }

    #[test]
    fn test_large_data() {
        let len = 127 * 1024;
        let src: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let mut dst_ref = vec![0u8; len];
        let mut dst_test = vec![0u8; len];
        reference_mad(&mut dst_ref, &src, 0x53);
        gf_vect_mad(&mut dst_test, &src, 0x53);
        assert_eq!(dst_ref, dst_test, "large data mismatch");
    }

    #[test]
    fn test_multi_large_group() {
        // Test with a larger group size to exercise the stack-allocated path
        let len = 1024;
        let src: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let n = 16;
        let coeffs: Vec<u8> = (1..=n as u8).collect();

        let mut dsts_seq: Vec<Vec<u8>> = (0..n).map(|_| vec![0u8; len]).collect();
        for (d, &c) in dsts_seq.iter_mut().zip(coeffs.iter()) {
            gf_vect_mad(d, &src, c);
        }

        let mut dsts_multi: Vec<Vec<u8>> = (0..n).map(|_| vec![0u8; len]).collect();
        let mut refs: Vec<&mut [u8]> = dsts_multi.iter_mut().map(|v| v.as_mut_slice()).collect();
        gf_vect_mad_multi(&mut refs, &src, &coeffs);

        for d in 0..n {
            assert_eq!(dsts_seq[d], dsts_multi[d], "multi mismatch at dst={d}");
        }
    }
}
