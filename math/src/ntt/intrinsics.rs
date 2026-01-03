//! Platform-specific intrinsics for NTT butterfly operations.
//!
//! This module provides optimized implementations of the NTT butterfly operation
//! for different CPU architectures. The butterfly is the core operation in the NTT:
//!
//! - Forward (FORWARD=true):  (a, b, w) -> (a + w*b, a - w*b)
//! - Inverse (FORWARD=false): (a, b, w) -> ((a + b)/2, (a - b)*w/2)
//!
//! # Platform Support
//!
//! - **aarch64 + NEON**: Vectorized implementation using ARM NEON intrinsics
//! - **x86_64 + AVX-512**: Vectorized implementation using AVX-512 intrinsics (8 elements/iter)
//! - **x86_64 + AVX2**: Vectorized implementation using AVX2 intrinsics (4 elements/iter)

use crate::fields::goldilocks::F;

// Goldilocks prime P = 2^64 - 2^32 + 1.
// Duplicated here to avoid cross-module const evaluation in intrinsics.
const P: u64 = u64::wrapping_neg(1 << 32) + 1;

/// Perform butterfly operations on slices.
///
/// When FORWARD=true (forward NTT):
///   For each index k: (a[k], b[k]) = (a[k] + w*b[k], a[k] - w*b[k])
///
/// When FORWARD=false (inverse NTT):
///   For each index k: (a[k], b[k]) = ((a[k] + b[k])/2, (a[k] - b[k])*w/2)
///
/// The slices must have the same length.
#[inline]
pub fn butterfly<const FORWARD: bool>(a: &mut [F], b: &mut [F], w: F) {
    debug_assert_eq!(a.len(), b.len());

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    {
        aarch64_neon::butterfly::<FORWARD>(a, b, w);
    }

    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx512f",
        not(target_arch = "aarch64")
    ))]
    {
        x86_64_avx512::butterfly::<FORWARD>(a, b, w);
    }

    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(target_feature = "avx512f"),
        not(target_arch = "aarch64")
    ))]
    {
        x86_64_avx2::butterfly::<FORWARD>(a, b, w);
    }

    #[cfg(not(any(
        all(target_arch = "aarch64", target_feature = "neon"),
        all(target_arch = "x86_64", target_feature = "avx512f"),
        all(target_arch = "x86_64", target_feature = "avx2")
    )))]
    {
        butterfly_scalar::<FORWARD>(a, b, w);
    }
}

/// Scalar fallback for butterfly operations.
#[inline]
fn butterfly_scalar<const FORWARD: bool>(a: &mut [F], b: &mut [F], w: F) {
    for (a_i, b_i) in a.iter_mut().zip(b.iter_mut()) {
        if FORWARD {
            let wb = w * *b_i;
            let new_a = *a_i + wb;
            let new_b = *a_i - wb;
            *a_i = new_a;
            *b_i = new_b;
        } else {
            let sum = *a_i + *b_i;
            let diff = *a_i - *b_i;
            *a_i = sum.div_2();
            *b_i = (diff * w).div_2();
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod aarch64_neon {
    use super::*;
    use core::arch::aarch64::*;

    /// Perform butterfly using NEON intrinsics.
    #[inline]
    pub fn butterfly<const FORWARD: bool>(a: &mut [F], b: &mut [F], w: F) {
        let len = a.len();
        let chunks = len / 2; // Process 2 elements per iteration (uint64x2_t)

        if chunks > 0 {
            // SAFETY: F is #[repr(transparent)] over u64, so &mut [F] has the same
            // layout as &mut [u64]. The pointers are valid for `chunks * 2` elements.
            let a_ptr = a.as_mut_ptr().cast::<u64>();
            let b_ptr = b.as_mut_ptr().cast::<u64>();

            // SAFETY: F is #[repr(transparent)] over u64
            let w_raw: u64 = unsafe { core::mem::transmute(w) };

            // SAFETY: Pointers are valid and properly aligned for u64 access.
            unsafe {
                butterfly_neon::<FORWARD>(a_ptr, b_ptr, w_raw, chunks);
            }
        }

        // Handle remainder with scalar code
        let processed = chunks * 2;
        if processed < len {
            super::butterfly_scalar::<FORWARD>(&mut a[processed..], &mut b[processed..], w);
        }
    }

    /// NEON butterfly implementation with 2× loop unrolling for better ILP.
    ///
    /// # Safety
    /// - `a` and `b` must point to valid memory for at least `chunks * 2` u64 elements
    /// - Pointers must be properly aligned for u64 access
    #[target_feature(enable = "neon")]
    unsafe fn butterfly_neon<const FORWARD: bool>(a: *mut u64, b: *mut u64, w: u64, chunks: usize) {
        let w_vec = vdupq_n_u64(w);

        // Process 2 vectors at a time (4 elements) for better instruction-level parallelism
        let chunks_2 = chunks / 2;
        for i in 0..chunks_2 {
            let offset0 = i * 4;
            let offset1 = offset0 + 2;

            // Load 2 pairs of vectors
            let a_vec0 = vld1q_u64(a.add(offset0));
            let b_vec0 = vld1q_u64(b.add(offset0));
            let a_vec1 = vld1q_u64(a.add(offset1));
            let b_vec1 = vld1q_u64(b.add(offset1));

            let (new_a0, new_b0, new_a1, new_b1) = if FORWARD {
                // Forward: (a + w*b, a - w*b)
                // Compute both multiplications first to maximize ILP
                let wb_vec0 = goldilocks_mul_vec(w_vec, b_vec0);
                let wb_vec1 = goldilocks_mul_vec(w_vec, b_vec1);
                // Then additions/subtractions
                let sum0 = goldilocks_add_vec(a_vec0, wb_vec0);
                let sum1 = goldilocks_add_vec(a_vec1, wb_vec1);
                let diff0 = goldilocks_sub_vec(a_vec0, wb_vec0);
                let diff1 = goldilocks_sub_vec(a_vec1, wb_vec1);
                (sum0, diff0, sum1, diff1)
            } else {
                // Inverse: ((a + b)/2, (a - b)*w/2)
                let sum0 = goldilocks_add_vec(a_vec0, b_vec0);
                let sum1 = goldilocks_add_vec(a_vec1, b_vec1);
                let diff0 = goldilocks_sub_vec(a_vec0, b_vec0);
                let diff1 = goldilocks_sub_vec(a_vec1, b_vec1);
                // Multiplications
                let diff_w0 = goldilocks_mul_vec(diff0, w_vec);
                let diff_w1 = goldilocks_mul_vec(diff1, w_vec);
                (
                    goldilocks_div2_vec(sum0),
                    goldilocks_div2_vec(diff_w0),
                    goldilocks_div2_vec(sum1),
                    goldilocks_div2_vec(diff_w1),
                )
            };

            // Store results
            vst1q_u64(a.add(offset0), new_a0);
            vst1q_u64(b.add(offset0), new_b0);
            vst1q_u64(a.add(offset1), new_a1);
            vst1q_u64(b.add(offset1), new_b1);
        }

        // Handle remaining single chunk if odd number of chunks
        if chunks % 2 != 0 {
            let offset = chunks_2 * 4;
            let a_vec = vld1q_u64(a.add(offset));
            let b_vec = vld1q_u64(b.add(offset));

            let (new_a, new_b) = if FORWARD {
                let wb_vec = goldilocks_mul_vec(w_vec, b_vec);
                let sum = goldilocks_add_vec(a_vec, wb_vec);
                let diff = goldilocks_sub_vec(a_vec, wb_vec);
                (sum, diff)
            } else {
                let sum = goldilocks_add_vec(a_vec, b_vec);
                let diff = goldilocks_sub_vec(a_vec, b_vec);
                let diff_w = goldilocks_mul_vec(diff, w_vec);
                (goldilocks_div2_vec(sum), goldilocks_div2_vec(diff_w))
            };

            vst1q_u64(a.add(offset), new_a);
            vst1q_u64(b.add(offset), new_b);
        }
    }

    /// Vectorized Goldilocks addition: (a + b) mod P
    ///
    /// Both inputs must be < P. Output is < P.
    #[inline(always)]
    unsafe fn goldilocks_add_vec(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
        let p_vec = vdupq_n_u64(P);

        // Compute a + b (wrapping). If this overflows, the true sum is (result + 2^64).
        let sum = vaddq_u64(a, b);
        let overflow = vcltq_u64(sum, a); // All 1s if overflow, all 0s otherwise

        // Compute sum - P (wrapping). If sum < P, this underflows.
        let reduced = vsubq_u64(sum, p_vec);
        let underflow = vcgtq_u64(reduced, sum); // All 1s if underflow (sum < P)

        // Use original sum if: no overflow AND sum < P (underflow in reduction)
        // Otherwise use the reduced value.
        let use_sum = vandq_u64(underflow, vmvnq_u8_as_u64(overflow));
        vbslq_u64(use_sum, sum, reduced)
    }

    /// Vectorized Goldilocks subtraction: (a - b) mod P
    ///
    /// Both inputs must be < P. Output is < P.
    #[inline(always)]
    unsafe fn goldilocks_sub_vec(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
        let p_vec = vdupq_n_u64(P);

        // Compute a - b (wrapping). If a < b, this underflows.
        let diff = vsubq_u64(a, b);
        let underflow = vcltq_u64(a, b);

        // If underflow, add P back to get the correct result.
        let corrected = vaddq_u64(diff, p_vec);
        vbslq_u64(underflow, corrected, diff)
    }

    /// Vectorized Goldilocks multiplication: (a * b) mod P
    ///
    /// Decomposes 64x64->128 bit multiplication into 32x32->64 bit products,
    /// then applies Goldilocks reduction.
    #[inline(always)]
    unsafe fn goldilocks_mul_vec(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
        // Split into 32-bit halves: x = x_lo + x_hi * 2^32
        let mask32 = vdupq_n_u64(0xFFFF_FFFF);
        let a_lo = vandq_u64(a, mask32);
        let a_hi = vshrq_n_u64(a, 32);
        let b_lo = vandq_u64(b, mask32);
        let b_hi = vshrq_n_u64(b, 32);

        // Compute four 32x32->64 products:
        // result = a_lo*b_lo + (a_lo*b_hi + a_hi*b_lo)*2^32 + a_hi*b_hi*2^64
        let a_lo_32 = vmovn_u64(a_lo);
        let a_hi_32 = vmovn_u64(a_hi);
        let b_lo_32 = vmovn_u64(b_lo);
        let b_hi_32 = vmovn_u64(b_hi);

        let p0 = vmull_u32(a_lo_32, b_lo_32); // bits 0-63
        let p1 = vmull_u32(a_lo_32, b_hi_32); // bits 32-95
        let p2 = vmull_u32(a_hi_32, b_lo_32); // bits 32-95
        let p3 = vmull_u32(a_hi_32, b_hi_32); // bits 64-127

        // Combine middle products: mid = p1 + p2
        let mid = vaddq_u64(p1, p2);
        let mid_lo = vshlq_n_u64(vandq_u64(mid, mask32), 32);
        let mid_hi = vshrq_n_u64(mid, 32);
        let mid_carry = vshrq_n_u64(vcltq_u64(mid, p1), 63); // 1 if overflow, else 0

        // Low 64 bits: lo = p0 + mid_lo
        let lo = vaddq_u64(p0, mid_lo);
        let lo_carry = vshrq_n_u64(vcltq_u64(lo, p0), 63);

        // High 64 bits: hi = p3 + mid_hi + lo_carry + mid_carry*2^32
        let hi = vaddq_u64(p3, mid_hi);
        let hi = vaddq_u64(hi, lo_carry);
        let hi = vaddq_u64(hi, vshlq_n_u64(mid_carry, 32));

        goldilocks_reduce_128_vec(lo, hi)
    }

    /// Reduce 128-bit value (lo + hi * 2^64) mod P.
    ///
    /// Uses Goldilocks identities:
    /// - 2^64 = 2^32 - 1 (mod P)
    /// - 2^96 = -1 (mod P)
    ///
    /// For x = c*2^96 + b*2^64 + a (where b = hi[31:0], c = hi[63:32], a = lo):
    /// x = a + b*(2^32 - 1) - c (mod P)
    #[inline(always)]
    unsafe fn goldilocks_reduce_128_vec(lo: uint64x2_t, hi: uint64x2_t) -> uint64x2_t {
        let mask32 = vdupq_n_u64(0xFFFF_FFFF);
        let p_vec = vdupq_n_u64(P);

        let a = lo;
        let b = vandq_u64(hi, mask32); // bits 64-95
        let c = vshrq_n_u64(hi, 32); // bits 96-127

        // b_term = b * (2^32 - 1) = (b << 32) - b
        let b_term = vsubq_u64(vshlq_n_u64(b, 32), b);

        // Compute a - c, handling underflow
        let a_minus_c = vsubq_u64(a, c);
        let underflow = vcltq_u64(a, c);
        // Add P back if underflow: mask is all 1s or all 0s, AND with P gives P or 0
        let correction = vandq_u64(underflow, p_vec);
        let a_minus_c = vaddq_u64(a_minus_c, correction);

        // Final result: (a - c) + b_term, with reduction
        goldilocks_add_vec(a_minus_c, b_term)
    }

    /// Vectorized Goldilocks division by 2.
    ///
    /// For field element x: returns x/2 = x * 2^(-1) mod P.
    /// If x is even, this is just x >> 1.
    /// If x is odd, this is (x + P) >> 1 (since P is odd, x + P is even).
    #[inline(always)]
    unsafe fn goldilocks_div2_vec(a: uint64x2_t) -> uint64x2_t {
        let one = vdupq_n_u64(1);
        let p_vec = vdupq_n_u64(P);
        let high_bit = vdupq_n_u64(1u64 << 63);

        // Check if odd
        let is_odd = vceqq_u64(vandq_u64(a, one), one);

        // For odd values: (a + P) >> 1, handling potential overflow
        let a_plus_p = vaddq_u64(a, p_vec);
        let overflow = vcltq_u64(a_plus_p, a);

        // If overflow, set high bit in result
        let shifted = vshrq_n_u64(a_plus_p, 1);
        let odd_result = vorrq_u64(shifted, vandq_u64(overflow, high_bit));

        // For even values: just shift
        let even_result = vshrq_n_u64(a, 1);

        vbslq_u64(is_odd, odd_result, even_result)
    }

    /// Bitwise NOT for uint64x2_t via reinterpret to u8.
    #[inline(always)]
    unsafe fn vmvnq_u8_as_u64(a: uint64x2_t) -> uint64x2_t {
        vreinterpretq_u64_u8(vmvnq_u8(vreinterpretq_u8_u64(a)))
    }
}

#[cfg(target_arch = "x86_64")]
mod x86_64_avx2 {
    use super::*;
    use core::arch::x86_64::*;

    /// Perform butterfly using AVX2 intrinsics.
    #[inline]
    pub fn butterfly<const FORWARD: bool>(a: &mut [F], b: &mut [F], w: F) {
        let len = a.len();
        let chunks = len / 4; // Process 4 elements per iteration (__m256i)

        if chunks > 0 {
            // SAFETY: F is #[repr(transparent)] over u64, so &mut [F] has the same
            // layout as &mut [u64]. The pointers are valid for `chunks * 4` elements.
            let a_ptr = a.as_mut_ptr().cast::<u64>();
            let b_ptr = b.as_mut_ptr().cast::<u64>();

            // SAFETY: F is #[repr(transparent)] over u64
            let w_raw: u64 = unsafe { core::mem::transmute(w) };

            // SAFETY: Pointers are valid and properly aligned for u64 access.
            unsafe {
                butterfly_avx2::<FORWARD>(a_ptr, b_ptr, w_raw, chunks);
            }
        }

        // Handle remainder with scalar code
        let processed = chunks * 4;
        if processed < len {
            super::butterfly_scalar::<FORWARD>(&mut a[processed..], &mut b[processed..], w);
        }
    }

    /// AVX2 butterfly implementation with 2× loop unrolling for better ILP.
    ///
    /// # Safety
    /// - `a` and `b` must point to valid memory for at least `chunks * 4` u64 elements
    /// - Pointers must be properly aligned for u64 access
    #[target_feature(enable = "avx2")]
    unsafe fn butterfly_avx2<const FORWARD: bool>(
        a: *mut u64,
        b: *mut u64,
        w: u64,
        chunks: usize,
    ) {
        let w_vec = _mm256_set1_epi64x(w as i64);

        // Process 2 vectors at a time (8 elements) for better instruction-level parallelism
        let chunks_2 = chunks / 2;
        for i in 0..chunks_2 {
            let offset0 = i * 8;
            let offset1 = offset0 + 4;

            // Load 2 pairs of vectors
            let a_vec0 = _mm256_loadu_si256(a.add(offset0).cast());
            let b_vec0 = _mm256_loadu_si256(b.add(offset0).cast());
            let a_vec1 = _mm256_loadu_si256(a.add(offset1).cast());
            let b_vec1 = _mm256_loadu_si256(b.add(offset1).cast());

            let (new_a0, new_b0, new_a1, new_b1) = if FORWARD {
                // Forward: (a + w*b, a - w*b)
                // Compute both multiplications first to maximize ILP
                let wb_vec0 = goldilocks_mul_vec(w_vec, b_vec0);
                let wb_vec1 = goldilocks_mul_vec(w_vec, b_vec1);
                // Then additions/subtractions
                let sum0 = goldilocks_add_vec(a_vec0, wb_vec0);
                let sum1 = goldilocks_add_vec(a_vec1, wb_vec1);
                let diff0 = goldilocks_sub_vec(a_vec0, wb_vec0);
                let diff1 = goldilocks_sub_vec(a_vec1, wb_vec1);
                (sum0, diff0, sum1, diff1)
            } else {
                // Inverse: ((a + b)/2, (a - b)*w/2)
                let sum0 = goldilocks_add_vec(a_vec0, b_vec0);
                let sum1 = goldilocks_add_vec(a_vec1, b_vec1);
                let diff0 = goldilocks_sub_vec(a_vec0, b_vec0);
                let diff1 = goldilocks_sub_vec(a_vec1, b_vec1);
                // Multiplications
                let diff_w0 = goldilocks_mul_vec(diff0, w_vec);
                let diff_w1 = goldilocks_mul_vec(diff1, w_vec);
                (
                    goldilocks_div2_vec(sum0),
                    goldilocks_div2_vec(diff_w0),
                    goldilocks_div2_vec(sum1),
                    goldilocks_div2_vec(diff_w1),
                )
            };

            // Store results
            _mm256_storeu_si256(a.add(offset0).cast(), new_a0);
            _mm256_storeu_si256(b.add(offset0).cast(), new_b0);
            _mm256_storeu_si256(a.add(offset1).cast(), new_a1);
            _mm256_storeu_si256(b.add(offset1).cast(), new_b1);
        }

        // Handle remaining single chunk if odd number of chunks
        if chunks % 2 != 0 {
            let offset = chunks_2 * 8;
            let a_vec = _mm256_loadu_si256(a.add(offset).cast());
            let b_vec = _mm256_loadu_si256(b.add(offset).cast());

            let (new_a, new_b) = if FORWARD {
                let wb_vec = goldilocks_mul_vec(w_vec, b_vec);
                let sum = goldilocks_add_vec(a_vec, wb_vec);
                let diff = goldilocks_sub_vec(a_vec, wb_vec);
                (sum, diff)
            } else {
                let sum = goldilocks_add_vec(a_vec, b_vec);
                let diff = goldilocks_sub_vec(a_vec, b_vec);
                let diff_w = goldilocks_mul_vec(diff, w_vec);
                (goldilocks_div2_vec(sum), goldilocks_div2_vec(diff_w))
            };

            _mm256_storeu_si256(a.add(offset).cast(), new_a);
            _mm256_storeu_si256(b.add(offset).cast(), new_b);
        }
    }

    /// Unsigned 64-bit compare: a < b
    ///
    /// AVX2 only has signed compare, so we XOR with sign bit to convert to unsigned.
    #[inline(always)]
    unsafe fn cmplt_epu64(a: __m256i, b: __m256i) -> __m256i {
        let sign_bit = _mm256_set1_epi64x(i64::MIN);
        let a_signed = _mm256_xor_si256(a, sign_bit);
        let b_signed = _mm256_xor_si256(b, sign_bit);
        _mm256_cmpgt_epi64(b_signed, a_signed)
    }

    /// Unsigned 64-bit compare: a > b
    #[inline(always)]
    unsafe fn cmpgt_epu64(a: __m256i, b: __m256i) -> __m256i {
        cmplt_epu64(b, a)
    }

    /// Vectorized Goldilocks addition: (a + b) mod P
    ///
    /// Both inputs must be < P. Output is < P.
    #[inline(always)]
    unsafe fn goldilocks_add_vec(a: __m256i, b: __m256i) -> __m256i {
        let p_vec = _mm256_set1_epi64x(P as i64);

        // Compute a + b (wrapping). If this overflows, the true sum is (result + 2^64).
        let sum = _mm256_add_epi64(a, b);
        let overflow = cmplt_epu64(sum, a); // All 1s if overflow, all 0s otherwise

        // Compute sum - P (wrapping). If sum < P, this underflows.
        let reduced = _mm256_sub_epi64(sum, p_vec);
        let underflow = cmpgt_epu64(reduced, sum); // All 1s if underflow (sum < P)

        // Use original sum if: no overflow AND sum < P (underflow in reduction)
        // Otherwise use the reduced value.
        let no_overflow = _mm256_xor_si256(overflow, _mm256_set1_epi64x(-1));
        let use_sum = _mm256_and_si256(underflow, no_overflow);
        _mm256_blendv_epi8(reduced, sum, use_sum)
    }

    /// Vectorized Goldilocks subtraction: (a - b) mod P
    ///
    /// Both inputs must be < P. Output is < P.
    #[inline(always)]
    unsafe fn goldilocks_sub_vec(a: __m256i, b: __m256i) -> __m256i {
        let p_vec = _mm256_set1_epi64x(P as i64);

        // Compute a - b (wrapping). If a < b, this underflows.
        let diff = _mm256_sub_epi64(a, b);
        let underflow = cmplt_epu64(a, b);

        // If underflow, add P back to get the correct result.
        let corrected = _mm256_add_epi64(diff, p_vec);
        _mm256_blendv_epi8(diff, corrected, underflow)
    }

    /// Vectorized Goldilocks multiplication: (a * b) mod P
    ///
    /// Decomposes 64x64->128 bit multiplication into 32x32->64 bit products,
    /// then applies Goldilocks reduction.
    #[inline(always)]
    unsafe fn goldilocks_mul_vec(a: __m256i, b: __m256i) -> __m256i {
        let mask32 = _mm256_set1_epi64x(0xFFFF_FFFF);

        // Split into 32-bit halves: x = x_lo + x_hi * 2^32
        let a_lo = _mm256_and_si256(a, mask32);
        let a_hi = _mm256_srli_epi64(a, 32);
        let b_lo = _mm256_and_si256(b, mask32);
        let b_hi = _mm256_srli_epi64(b, 32);

        // Compute four 32x32->64 products using _mm256_mul_epu32.
        // _mm256_mul_epu32 multiplies the low 32 bits of each 64-bit lane.
        let p0 = _mm256_mul_epu32(a_lo, b_lo); // a_lo * b_lo (bits 0-63)
        let p1 = _mm256_mul_epu32(a_lo, b_hi); // a_lo * b_hi (bits 32-95)
        let p2 = _mm256_mul_epu32(a_hi, b_lo); // a_hi * b_lo (bits 32-95)
        let p3 = _mm256_mul_epu32(a_hi, b_hi); // a_hi * b_hi (bits 64-127)

        // Combine middle products: mid = p1 + p2
        let mid = _mm256_add_epi64(p1, p2);
        let mid_lo = _mm256_slli_epi64(_mm256_and_si256(mid, mask32), 32);
        let mid_hi = _mm256_srli_epi64(mid, 32);
        // Detect carry from p1 + p2
        let mid_carry = _mm256_srli_epi64(cmplt_epu64(mid, p1), 63);

        // Low 64 bits: lo = p0 + mid_lo
        let lo = _mm256_add_epi64(p0, mid_lo);
        let lo_carry = _mm256_srli_epi64(cmplt_epu64(lo, p0), 63);

        // High 64 bits: hi = p3 + mid_hi + lo_carry + mid_carry*2^32
        let hi = _mm256_add_epi64(p3, mid_hi);
        let hi = _mm256_add_epi64(hi, lo_carry);
        let hi = _mm256_add_epi64(hi, _mm256_slli_epi64(mid_carry, 32));

        goldilocks_reduce_128_vec(lo, hi)
    }

    /// Reduce 128-bit value (lo + hi * 2^64) mod P.
    ///
    /// Uses Goldilocks identities:
    /// - 2^64 = 2^32 - 1 (mod P)
    /// - 2^96 = -1 (mod P)
    ///
    /// For x = c*2^96 + b*2^64 + a (where b = hi[31:0], c = hi[63:32], a = lo):
    /// x = a + b*(2^32 - 1) - c (mod P)
    #[inline(always)]
    unsafe fn goldilocks_reduce_128_vec(lo: __m256i, hi: __m256i) -> __m256i {
        let mask32 = _mm256_set1_epi64x(0xFFFF_FFFF);
        let p_vec = _mm256_set1_epi64x(P as i64);

        let a = lo;
        let b = _mm256_and_si256(hi, mask32); // bits 64-95
        let c = _mm256_srli_epi64(hi, 32); // bits 96-127

        // b_term = b * (2^32 - 1) = (b << 32) - b
        let b_term = _mm256_sub_epi64(_mm256_slli_epi64(b, 32), b);

        // Compute a - c, handling underflow
        let a_minus_c = _mm256_sub_epi64(a, c);
        let underflow = cmplt_epu64(a, c);
        // Add P back if underflow
        let correction = _mm256_and_si256(underflow, p_vec);
        let a_minus_c = _mm256_add_epi64(a_minus_c, correction);

        // Final result: (a - c) + b_term, with reduction
        goldilocks_add_vec(a_minus_c, b_term)
    }

    /// Vectorized Goldilocks division by 2.
    ///
    /// For field element x: returns x/2 = x * 2^(-1) mod P.
    /// If x is even, this is just x >> 1.
    /// If x is odd, this is (x + P) >> 1 (since P is odd, x + P is even).
    #[inline(always)]
    unsafe fn goldilocks_div2_vec(a: __m256i) -> __m256i {
        let one = _mm256_set1_epi64x(1);
        let p_vec = _mm256_set1_epi64x(P as i64);
        let high_bit = _mm256_set1_epi64x(1i64 << 63);

        // Check if odd
        let is_odd = _mm256_cmpeq_epi64(_mm256_and_si256(a, one), one);

        // For odd values: (a + P) >> 1, handling potential overflow
        let a_plus_p = _mm256_add_epi64(a, p_vec);
        let overflow = cmplt_epu64(a_plus_p, a);

        // If overflow, set high bit in result
        let shifted = _mm256_srli_epi64(a_plus_p, 1);
        let odd_result = _mm256_or_si256(shifted, _mm256_and_si256(overflow, high_bit));

        // For even values: just shift
        let even_result = _mm256_srli_epi64(a, 1);

        _mm256_blendv_epi8(even_result, odd_result, is_odd)
    }
}

#[cfg(target_arch = "x86_64")]
mod x86_64_avx512 {
    use super::*;
    use core::arch::x86_64::*;

    /// Perform butterfly using AVX-512 intrinsics.
    #[inline]
    pub fn butterfly<const FORWARD: bool>(a: &mut [F], b: &mut [F], w: F) {
        let len = a.len();
        let chunks = len / 8; // Process 8 elements per iteration (__m512i)

        if chunks > 0 {
            // SAFETY: F is #[repr(transparent)] over u64, so &mut [F] has the same
            // layout as &mut [u64]. The pointers are valid for `chunks * 8` elements.
            let a_ptr = a.as_mut_ptr().cast::<u64>();
            let b_ptr = b.as_mut_ptr().cast::<u64>();

            // SAFETY: F is #[repr(transparent)] over u64
            let w_raw: u64 = unsafe { core::mem::transmute(w) };

            // SAFETY: Pointers are valid and properly aligned for u64 access.
            unsafe {
                butterfly_avx512::<FORWARD>(a_ptr, b_ptr, w_raw, chunks);
            }
        }

        // Handle remainder with AVX2 if available, otherwise scalar
        let processed = chunks * 8;
        if processed < len {
            super::x86_64_avx2::butterfly::<FORWARD>(&mut a[processed..], &mut b[processed..], w);
        }
    }

    /// AVX-512 butterfly implementation with 2× loop unrolling for better ILP.
    ///
    /// # Safety
    /// - `a` and `b` must point to valid memory for at least `chunks * 8` u64 elements
    /// - Pointers must be properly aligned for u64 access
    #[target_feature(enable = "avx512f")]
    unsafe fn butterfly_avx512<const FORWARD: bool>(
        a: *mut u64,
        b: *mut u64,
        w: u64,
        chunks: usize,
    ) {
        let w_vec = _mm512_set1_epi64(w as i64);

        // Process 2 vectors at a time (16 elements) for better instruction-level parallelism
        let chunks_2 = chunks / 2;
        for i in 0..chunks_2 {
            let offset0 = i * 16;
            let offset1 = offset0 + 8;

            // Load 2 pairs of vectors
            let a_vec0 = _mm512_loadu_si512(a.add(offset0).cast());
            let b_vec0 = _mm512_loadu_si512(b.add(offset0).cast());
            let a_vec1 = _mm512_loadu_si512(a.add(offset1).cast());
            let b_vec1 = _mm512_loadu_si512(b.add(offset1).cast());

            let (new_a0, new_b0, new_a1, new_b1) = if FORWARD {
                // Forward: (a + w*b, a - w*b)
                // Compute both multiplications first to maximize ILP
                let wb_vec0 = goldilocks_mul_vec(w_vec, b_vec0);
                let wb_vec1 = goldilocks_mul_vec(w_vec, b_vec1);
                // Then additions/subtractions
                let sum0 = goldilocks_add_vec(a_vec0, wb_vec0);
                let sum1 = goldilocks_add_vec(a_vec1, wb_vec1);
                let diff0 = goldilocks_sub_vec(a_vec0, wb_vec0);
                let diff1 = goldilocks_sub_vec(a_vec1, wb_vec1);
                (sum0, diff0, sum1, diff1)
            } else {
                // Inverse: ((a + b)/2, (a - b)*w/2)
                let sum0 = goldilocks_add_vec(a_vec0, b_vec0);
                let sum1 = goldilocks_add_vec(a_vec1, b_vec1);
                let diff0 = goldilocks_sub_vec(a_vec0, b_vec0);
                let diff1 = goldilocks_sub_vec(a_vec1, b_vec1);
                // Multiplications
                let diff_w0 = goldilocks_mul_vec(diff0, w_vec);
                let diff_w1 = goldilocks_mul_vec(diff1, w_vec);
                (
                    goldilocks_div2_vec(sum0),
                    goldilocks_div2_vec(diff_w0),
                    goldilocks_div2_vec(sum1),
                    goldilocks_div2_vec(diff_w1),
                )
            };

            // Store results
            _mm512_storeu_si512(a.add(offset0).cast(), new_a0);
            _mm512_storeu_si512(b.add(offset0).cast(), new_b0);
            _mm512_storeu_si512(a.add(offset1).cast(), new_a1);
            _mm512_storeu_si512(b.add(offset1).cast(), new_b1);
        }

        // Handle remaining single chunk if odd number of chunks
        if chunks % 2 != 0 {
            let offset = chunks_2 * 16;
            let a_vec = _mm512_loadu_si512(a.add(offset).cast());
            let b_vec = _mm512_loadu_si512(b.add(offset).cast());

            let (new_a, new_b) = if FORWARD {
                let wb_vec = goldilocks_mul_vec(w_vec, b_vec);
                let sum = goldilocks_add_vec(a_vec, wb_vec);
                let diff = goldilocks_sub_vec(a_vec, wb_vec);
                (sum, diff)
            } else {
                let sum = goldilocks_add_vec(a_vec, b_vec);
                let diff = goldilocks_sub_vec(a_vec, b_vec);
                let diff_w = goldilocks_mul_vec(diff, w_vec);
                (goldilocks_div2_vec(sum), goldilocks_div2_vec(diff_w))
            };

            _mm512_storeu_si512(a.add(offset).cast(), new_a);
            _mm512_storeu_si512(b.add(offset).cast(), new_b);
        }
    }

    /// Vectorized Goldilocks addition: (a + b) mod P
    ///
    /// Both inputs must be < P. Output is < P.
    #[inline(always)]
    unsafe fn goldilocks_add_vec(a: __m512i, b: __m512i) -> __m512i {
        let p_vec = _mm512_set1_epi64(P as i64);

        // Compute a + b (wrapping). If this overflows, the true sum is (result + 2^64).
        let sum = _mm512_add_epi64(a, b);

        // AVX-512 has native unsigned compare returning a mask
        let overflow_mask = _mm512_cmplt_epu64_mask(sum, a);

        // Compute sum - P (wrapping). If sum < P, this underflows.
        let reduced = _mm512_sub_epi64(sum, p_vec);
        let underflow_mask = _mm512_cmpgt_epu64_mask(reduced, sum);

        // Use original sum if: no overflow AND sum < P (underflow in reduction)
        // Otherwise use the reduced value.
        let use_sum_mask = underflow_mask & !overflow_mask;
        _mm512_mask_blend_epi64(use_sum_mask, reduced, sum)
    }

    /// Vectorized Goldilocks subtraction: (a - b) mod P
    ///
    /// Both inputs must be < P. Output is < P.
    #[inline(always)]
    unsafe fn goldilocks_sub_vec(a: __m512i, b: __m512i) -> __m512i {
        let p_vec = _mm512_set1_epi64(P as i64);

        // Compute a - b (wrapping). If a < b, this underflows.
        let diff = _mm512_sub_epi64(a, b);
        let underflow_mask = _mm512_cmplt_epu64_mask(a, b);

        // If underflow, add P back to get the correct result.
        let corrected = _mm512_add_epi64(diff, p_vec);
        _mm512_mask_blend_epi64(underflow_mask, diff, corrected)
    }

    /// Vectorized Goldilocks multiplication: (a * b) mod P
    ///
    /// Decomposes 64x64->128 bit multiplication into 32x32->64 bit products,
    /// then applies Goldilocks reduction.
    #[inline(always)]
    unsafe fn goldilocks_mul_vec(a: __m512i, b: __m512i) -> __m512i {
        let mask32 = _mm512_set1_epi64(0xFFFF_FFFF);

        // Split into 32-bit halves: x = x_lo + x_hi * 2^32
        let a_lo = _mm512_and_si512(a, mask32);
        let a_hi = _mm512_srli_epi64(a, 32);
        let b_lo = _mm512_and_si512(b, mask32);
        let b_hi = _mm512_srli_epi64(b, 32);

        // Compute four 32x32->64 products using _mm512_mul_epu32.
        let p0 = _mm512_mul_epu32(a_lo, b_lo); // a_lo * b_lo (bits 0-63)
        let p1 = _mm512_mul_epu32(a_lo, b_hi); // a_lo * b_hi (bits 32-95)
        let p2 = _mm512_mul_epu32(a_hi, b_lo); // a_hi * b_lo (bits 32-95)
        let p3 = _mm512_mul_epu32(a_hi, b_hi); // a_hi * b_hi (bits 64-127)

        // Combine middle products: mid = p1 + p2
        let mid = _mm512_add_epi64(p1, p2);
        let mid_lo = _mm512_slli_epi64(_mm512_and_si512(mid, mask32), 32);
        let mid_hi = _mm512_srli_epi64(mid, 32);
        // Detect carry from p1 + p2 using unsigned compare
        let mid_carry_mask = _mm512_cmplt_epu64_mask(mid, p1);
        let mid_carry = _mm512_maskz_set1_epi64(mid_carry_mask, 1);

        // Low 64 bits: lo = p0 + mid_lo
        let lo = _mm512_add_epi64(p0, mid_lo);
        let lo_carry_mask = _mm512_cmplt_epu64_mask(lo, p0);
        let lo_carry = _mm512_maskz_set1_epi64(lo_carry_mask, 1);

        // High 64 bits: hi = p3 + mid_hi + lo_carry + mid_carry*2^32
        let hi = _mm512_add_epi64(p3, mid_hi);
        let hi = _mm512_add_epi64(hi, lo_carry);
        let hi = _mm512_add_epi64(hi, _mm512_slli_epi64(mid_carry, 32));

        goldilocks_reduce_128_vec(lo, hi)
    }

    /// Reduce 128-bit value (lo + hi * 2^64) mod P.
    ///
    /// Uses Goldilocks identities:
    /// - 2^64 = 2^32 - 1 (mod P)
    /// - 2^96 = -1 (mod P)
    #[inline(always)]
    unsafe fn goldilocks_reduce_128_vec(lo: __m512i, hi: __m512i) -> __m512i {
        let mask32 = _mm512_set1_epi64(0xFFFF_FFFF);
        let p_vec = _mm512_set1_epi64(P as i64);

        let a = lo;
        let b = _mm512_and_si512(hi, mask32); // bits 64-95
        let c = _mm512_srli_epi64(hi, 32); // bits 96-127

        // b_term = b * (2^32 - 1) = (b << 32) - b
        let b_term = _mm512_sub_epi64(_mm512_slli_epi64(b, 32), b);

        // Compute a - c, handling underflow
        let a_minus_c = _mm512_sub_epi64(a, c);
        let underflow_mask = _mm512_cmplt_epu64_mask(a, c);
        // Add P back if underflow
        let a_minus_c = _mm512_mask_add_epi64(a_minus_c, underflow_mask, a_minus_c, p_vec);

        // Final result: (a - c) + b_term, with reduction
        goldilocks_add_vec(a_minus_c, b_term)
    }

    /// Vectorized Goldilocks division by 2.
    #[inline(always)]
    unsafe fn goldilocks_div2_vec(a: __m512i) -> __m512i {
        let one = _mm512_set1_epi64(1);
        let p_vec = _mm512_set1_epi64(P as i64);
        let high_bit = _mm512_set1_epi64(1i64 << 63);

        // Check if odd
        let is_odd_mask = _mm512_cmpeq_epi64_mask(_mm512_and_si512(a, one), one);

        // For odd values: (a + P) >> 1, handling potential overflow
        let a_plus_p = _mm512_add_epi64(a, p_vec);
        let overflow_mask = _mm512_cmplt_epu64_mask(a_plus_p, a);

        // If overflow, set high bit in result
        let shifted = _mm512_srli_epi64(a_plus_p, 1);
        let overflow_high = _mm512_maskz_mov_epi64(overflow_mask, high_bit);
        let odd_result = _mm512_or_si512(shifted, overflow_high);

        // For even values: just shift
        let even_result = _mm512_srli_epi64(a, 1);

        _mm512_mask_blend_epi64(is_odd_mask, even_result, odd_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_butterfly_forward_scalar() {
        let w = F::from(7u64);
        let mut a = vec![F::from(3u64), F::from(5u64), F::from(11u64)];
        let mut b = vec![F::from(2u64), F::from(4u64), F::from(6u64)];

        let expected_a: Vec<F> = a
            .iter()
            .zip(b.iter())
            .map(|(&ai, &bi)| ai + w * bi)
            .collect();
        let expected_b: Vec<F> = a
            .iter()
            .zip(b.iter())
            .map(|(&ai, &bi)| ai - w * bi)
            .collect();

        butterfly_scalar::<true>(&mut a, &mut b, w);

        assert_eq!(a, expected_a);
        assert_eq!(b, expected_b);
    }

    #[test]
    fn test_butterfly_inverse_scalar() {
        let w = F::from(7u64);
        let mut a = vec![F::from(17u64), F::from(33u64), F::from(53u64)];
        let mut b = vec![F::from(3u64), F::from(5u64), F::from(11u64)];

        let expected_a: Vec<F> = a
            .iter()
            .zip(b.iter())
            .map(|(&ai, &bi)| (ai + bi).div_2())
            .collect();
        let expected_b: Vec<F> = a
            .iter()
            .zip(b.iter())
            .map(|(&ai, &bi)| ((ai - bi) * w).div_2())
            .collect();

        butterfly_scalar::<false>(&mut a, &mut b, w);

        assert_eq!(a, expected_a);
        assert_eq!(b, expected_b);
    }

    #[test]
    fn test_butterfly_roundtrip() {
        let w = F::from(7u64);
        let w_inv = w.inv();

        let original_a = vec![F::from(100u64), F::from(200u64)];
        let original_b = vec![F::from(300u64), F::from(400u64)];

        let mut a = original_a.clone();
        let mut b = original_b.clone();

        butterfly::<true>(&mut a, &mut b, w);
        butterfly::<false>(&mut a, &mut b, w_inv);

        assert_eq!(a, original_a);
        assert_eq!(b, original_b);
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    mod neon_tests {
        use super::*;

        #[test]
        fn test_neon_forward_matches_scalar() {
            let w = F::from(12345u64);
            let mut a_neon = vec![
                F::from(111u64),
                F::from(222u64),
                F::from(333u64),
                F::from(444u64),
            ];
            let mut b_neon = vec![
                F::from(555u64),
                F::from(666u64),
                F::from(777u64),
                F::from(888u64),
            ];
            let mut a_scalar = a_neon.clone();
            let mut b_scalar = b_neon.clone();

            butterfly::<true>(&mut a_neon, &mut b_neon, w);
            butterfly_scalar::<true>(&mut a_scalar, &mut b_scalar, w);

            assert_eq!(a_neon, a_scalar);
            assert_eq!(b_neon, b_scalar);
        }

        #[test]
        fn test_neon_inverse_matches_scalar() {
            let w = F::from(12345u64);
            let mut a_neon = vec![
                F::from(111u64),
                F::from(222u64),
                F::from(333u64),
                F::from(444u64),
            ];
            let mut b_neon = vec![
                F::from(555u64),
                F::from(666u64),
                F::from(777u64),
                F::from(888u64),
            ];
            let mut a_scalar = a_neon.clone();
            let mut b_scalar = b_neon.clone();

            butterfly::<false>(&mut a_neon, &mut b_neon, w);
            butterfly_scalar::<false>(&mut a_scalar, &mut b_scalar, w);

            assert_eq!(a_neon, a_scalar);
            assert_eq!(b_neon, b_scalar);
        }

        #[test]
        fn test_neon_with_large_values() {
            // Test with values near P to stress reduction
            let large = F::from(u64::MAX);
            let w = F::from(0xABCD_EF01_2345_6789u64);

            let mut a = vec![large; 4];
            let mut b = vec![large; 4];
            let mut a_scalar = a.clone();
            let mut b_scalar = b.clone();

            butterfly::<true>(&mut a, &mut b, w);
            butterfly_scalar::<true>(&mut a_scalar, &mut b_scalar, w);

            assert_eq!(a, a_scalar);
            assert_eq!(b, b_scalar);
        }

        #[test]
        fn test_neon_with_zeros() {
            let w = F::from(12345u64);
            let mut a = vec![F::from(0u64); 4];
            let mut b = vec![F::from(0u64); 4];
            let mut a_scalar = a.clone();
            let mut b_scalar = b.clone();

            butterfly::<true>(&mut a, &mut b, w);
            butterfly_scalar::<true>(&mut a_scalar, &mut b_scalar, w);

            assert_eq!(a, a_scalar);
            assert_eq!(b, b_scalar);
        }

        #[test]
        fn test_neon_odd_length() {
            // Test with odd-length slices to exercise remainder handling
            let w = F::from(42u64);
            let mut a = vec![F::from(1u64), F::from(2u64), F::from(3u64)];
            let mut b = vec![F::from(4u64), F::from(5u64), F::from(6u64)];
            let mut a_scalar = a.clone();
            let mut b_scalar = b.clone();

            butterfly::<true>(&mut a, &mut b, w);
            butterfly_scalar::<true>(&mut a_scalar, &mut b_scalar, w);

            assert_eq!(a, a_scalar);
            assert_eq!(b, b_scalar);
        }
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    mod avx2_tests {
        use super::*;

        #[test]
        fn test_avx2_forward_matches_scalar() {
            let w = F::from(12345u64);
            // 8 elements to test both full AVX2 iterations and remainder
            let mut a_avx2 = vec![
                F::from(111u64),
                F::from(222u64),
                F::from(333u64),
                F::from(444u64),
                F::from(555u64),
                F::from(666u64),
                F::from(777u64),
                F::from(888u64),
            ];
            let mut b_avx2 = vec![
                F::from(1111u64),
                F::from(2222u64),
                F::from(3333u64),
                F::from(4444u64),
                F::from(5555u64),
                F::from(6666u64),
                F::from(7777u64),
                F::from(8888u64),
            ];
            let mut a_scalar = a_avx2.clone();
            let mut b_scalar = b_avx2.clone();

            butterfly::<true>(&mut a_avx2, &mut b_avx2, w);
            butterfly_scalar::<true>(&mut a_scalar, &mut b_scalar, w);

            assert_eq!(a_avx2, a_scalar);
            assert_eq!(b_avx2, b_scalar);
        }

        #[test]
        fn test_avx2_inverse_matches_scalar() {
            let w = F::from(12345u64);
            let mut a_avx2 = vec![
                F::from(111u64),
                F::from(222u64),
                F::from(333u64),
                F::from(444u64),
                F::from(555u64),
                F::from(666u64),
                F::from(777u64),
                F::from(888u64),
            ];
            let mut b_avx2 = vec![
                F::from(1111u64),
                F::from(2222u64),
                F::from(3333u64),
                F::from(4444u64),
                F::from(5555u64),
                F::from(6666u64),
                F::from(7777u64),
                F::from(8888u64),
            ];
            let mut a_scalar = a_avx2.clone();
            let mut b_scalar = b_avx2.clone();

            butterfly::<false>(&mut a_avx2, &mut b_avx2, w);
            butterfly_scalar::<false>(&mut a_scalar, &mut b_scalar, w);

            assert_eq!(a_avx2, a_scalar);
            assert_eq!(b_avx2, b_scalar);
        }

        #[test]
        fn test_avx2_with_large_values() {
            // Test with values near P to stress reduction
            let large = F::from(u64::MAX);
            let w = F::from(0xABCD_EF01_2345_6789u64);

            let mut a = vec![large; 8];
            let mut b = vec![large; 8];
            let mut a_scalar = a.clone();
            let mut b_scalar = b.clone();

            butterfly::<true>(&mut a, &mut b, w);
            butterfly_scalar::<true>(&mut a_scalar, &mut b_scalar, w);

            assert_eq!(a, a_scalar);
            assert_eq!(b, b_scalar);
        }

        #[test]
        fn test_avx2_with_zeros() {
            let w = F::from(12345u64);
            let mut a = vec![F::from(0u64); 8];
            let mut b = vec![F::from(0u64); 8];
            let mut a_scalar = a.clone();
            let mut b_scalar = b.clone();

            butterfly::<true>(&mut a, &mut b, w);
            butterfly_scalar::<true>(&mut a_scalar, &mut b_scalar, w);

            assert_eq!(a, a_scalar);
            assert_eq!(b, b_scalar);
        }

        #[test]
        fn test_avx2_remainder_handling() {
            // Test with 5 elements: 1 full AVX2 iteration + 1 remainder
            let w = F::from(42u64);
            let mut a = vec![
                F::from(1u64),
                F::from(2u64),
                F::from(3u64),
                F::from(4u64),
                F::from(5u64),
            ];
            let mut b = vec![
                F::from(6u64),
                F::from(7u64),
                F::from(8u64),
                F::from(9u64),
                F::from(10u64),
            ];
            let mut a_scalar = a.clone();
            let mut b_scalar = b.clone();

            butterfly::<true>(&mut a, &mut b, w);
            butterfly_scalar::<true>(&mut a_scalar, &mut b_scalar, w);

            assert_eq!(a, a_scalar);
            assert_eq!(b, b_scalar);
        }

        #[test]
        fn test_avx2_roundtrip() {
            let w = F::from(7u64);
            let w_inv = w.inv();

            let original_a: Vec<F> = (0..8).map(|i| F::from(100 + i)).collect();
            let original_b: Vec<F> = (0..8).map(|i| F::from(200 + i)).collect();

            let mut a = original_a.clone();
            let mut b = original_b.clone();

            butterfly::<true>(&mut a, &mut b, w);
            butterfly::<false>(&mut a, &mut b, w_inv);

            assert_eq!(a, original_a);
            assert_eq!(b, original_b);
        }
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    mod avx512_tests {
        use super::*;

        #[test]
        fn test_avx512_forward_matches_scalar() {
            let w = F::from(12345u64);
            // 16 elements to test full AVX-512 iterations
            let mut a_avx512: Vec<F> = (0..16).map(|i| F::from(100 + i)).collect();
            let mut b_avx512: Vec<F> = (0..16).map(|i| F::from(1000 + i)).collect();
            let mut a_scalar = a_avx512.clone();
            let mut b_scalar = b_avx512.clone();

            butterfly::<true>(&mut a_avx512, &mut b_avx512, w);
            butterfly_scalar::<true>(&mut a_scalar, &mut b_scalar, w);

            assert_eq!(a_avx512, a_scalar);
            assert_eq!(b_avx512, b_scalar);
        }

        #[test]
        fn test_avx512_inverse_matches_scalar() {
            let w = F::from(12345u64);
            let mut a_avx512: Vec<F> = (0..16).map(|i| F::from(100 + i)).collect();
            let mut b_avx512: Vec<F> = (0..16).map(|i| F::from(1000 + i)).collect();
            let mut a_scalar = a_avx512.clone();
            let mut b_scalar = b_avx512.clone();

            butterfly::<false>(&mut a_avx512, &mut b_avx512, w);
            butterfly_scalar::<false>(&mut a_scalar, &mut b_scalar, w);

            assert_eq!(a_avx512, a_scalar);
            assert_eq!(b_avx512, b_scalar);
        }

        #[test]
        fn test_avx512_with_large_values() {
            let large = F::from(u64::MAX);
            let w = F::from(0xABCD_EF01_2345_6789u64);

            let mut a = vec![large; 16];
            let mut b = vec![large; 16];
            let mut a_scalar = a.clone();
            let mut b_scalar = b.clone();

            butterfly::<true>(&mut a, &mut b, w);
            butterfly_scalar::<true>(&mut a_scalar, &mut b_scalar, w);

            assert_eq!(a, a_scalar);
            assert_eq!(b, b_scalar);
        }

        #[test]
        fn test_avx512_with_zeros() {
            let w = F::from(12345u64);
            let mut a = vec![F::from(0u64); 16];
            let mut b = vec![F::from(0u64); 16];
            let mut a_scalar = a.clone();
            let mut b_scalar = b.clone();

            butterfly::<true>(&mut a, &mut b, w);
            butterfly_scalar::<true>(&mut a_scalar, &mut b_scalar, w);

            assert_eq!(a, a_scalar);
            assert_eq!(b, b_scalar);
        }

        #[test]
        fn test_avx512_remainder_handling() {
            // Test with 10 elements: 1 full AVX-512 iteration + 2 remainder handled by AVX2
            let w = F::from(42u64);
            let mut a: Vec<F> = (0..10).map(|i| F::from(i + 1)).collect();
            let mut b: Vec<F> = (0..10).map(|i| F::from(i + 11)).collect();
            let mut a_scalar = a.clone();
            let mut b_scalar = b.clone();

            butterfly::<true>(&mut a, &mut b, w);
            butterfly_scalar::<true>(&mut a_scalar, &mut b_scalar, w);

            assert_eq!(a, a_scalar);
            assert_eq!(b, b_scalar);
        }

        #[test]
        fn test_avx512_roundtrip() {
            let w = F::from(7u64);
            let w_inv = w.inv();

            let original_a: Vec<F> = (0..16).map(|i| F::from(100 + i)).collect();
            let original_b: Vec<F> = (0..16).map(|i| F::from(200 + i)).collect();

            let mut a = original_a.clone();
            let mut b = original_b.clone();

            butterfly::<true>(&mut a, &mut b, w);
            butterfly::<false>(&mut a, &mut b, w_inv);

            assert_eq!(a, original_a);
            assert_eq!(b, original_b);
        }
    }
}
