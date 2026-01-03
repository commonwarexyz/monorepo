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

use crate::fields::goldilocks::F;

/// The Goldilocks prime P = 2^64 - 2^32 + 1
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

    #[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
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

// ARM64 NEON implementation
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod aarch64_neon {
    use super::*;
    use core::arch::aarch64::*;

    /// Number of field elements processed per NEON iteration.
    /// We process 2 elements at a time using 128-bit registers.
    const LANE_COUNT: usize = 2;

    /// Perform butterfly using NEON intrinsics.
    #[inline]
    pub fn butterfly<const FORWARD: bool>(a: &mut [F], b: &mut [F], w: F) {
        let len = a.len();

        // Process pairs of elements with NEON
        let chunks = len / LANE_COUNT;
        if chunks > 0 {
            // SAFETY: F is repr(transparent) over u64, so &[F] can be reinterpreted as &[u64]
            let a_ptr = a.as_mut_ptr() as *mut u64;
            let b_ptr = b.as_mut_ptr() as *mut u64;
            let w_raw = field_to_raw(w);

            // SAFETY: Pointers are valid and aligned, chunks is computed correctly
            unsafe {
                butterfly_neon::<FORWARD>(a_ptr, b_ptr, w_raw, chunks);
            }
        }

        // Handle remainder with scalar code
        let processed = chunks * LANE_COUNT;
        if processed < len {
            super::butterfly_scalar::<FORWARD>(&mut a[processed..], &mut b[processed..], w);
        }
    }

    /// Extract raw u64 value from field element.
    #[inline(always)]
    fn field_to_raw(f: F) -> u64 {
        // SAFETY: F is repr(transparent) over u64
        unsafe { core::mem::transmute(f) }
    }

    /// NEON butterfly implementation.
    ///
    /// # Safety
    /// - `a` and `b` must point to valid memory for at least `chunks * 2` u64 elements
    /// - Pointers must be properly aligned for u64 access
    #[target_feature(enable = "neon")]
    unsafe fn butterfly_neon<const FORWARD: bool>(
        a: *mut u64,
        b: *mut u64,
        w: u64,
        chunks: usize,
    ) {
        let w_vec = vdupq_n_u64(w);

        for i in 0..chunks {
            let offset = i * LANE_COUNT;

            let a_vec = vld1q_u64(a.add(offset));
            let b_vec = vld1q_u64(b.add(offset));

            let (new_a, new_b) = if FORWARD {
                // Forward: (a + w*b, a - w*b)
                let wb_vec = goldilocks_mul_vec(w_vec, b_vec);
                let sum_vec = goldilocks_add_vec(a_vec, wb_vec);
                let diff_vec = goldilocks_sub_vec(a_vec, wb_vec);
                (sum_vec, diff_vec)
            } else {
                // Inverse: ((a + b)/2, (a - b)*w/2)
                let sum_vec = goldilocks_add_vec(a_vec, b_vec);
                let diff_vec = goldilocks_sub_vec(a_vec, b_vec);
                let diff_w_vec = goldilocks_mul_vec(diff_vec, w_vec);
                let sum_div2 = goldilocks_div2_vec(sum_vec);
                let diff_w_div2 = goldilocks_div2_vec(diff_w_vec);
                (sum_div2, diff_w_div2)
            };

            vst1q_u64(a.add(offset), new_a);
            vst1q_u64(b.add(offset), new_b);
        }
    }

    /// Vectorized Goldilocks addition: (a + b) mod P
    #[inline(always)]
    unsafe fn goldilocks_add_vec(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
        // addition = a + b (wrapping)
        let addition = vaddq_u64(a, b);

        // Check for overflow: if addition < a, overflow occurred
        let overflow = vcltq_u64(addition, a);

        // subtraction = addition - P (wrapping)
        let p_vec = vdupq_n_u64(P);
        let subtraction = vsubq_u64(addition, p_vec);

        // Check for underflow: if subtraction > addition, underflow occurred
        let underflow = vcgtq_u64(subtraction, addition);

        // Use original (addition) if: !overflow AND underflow
        // Otherwise use subtraction
        let not_overflow = not_u64(overflow);
        let use_original = vandq_u64(underflow, not_overflow);

        // Select: use addition if use_original, else subtraction
        vbslq_u64(use_original, addition, subtraction)
    }

    /// Bitwise NOT for uint64x2_t (NEON doesn't have vmvnq_u64)
    #[inline(always)]
    unsafe fn not_u64(a: uint64x2_t) -> uint64x2_t {
        let as_u8 = vreinterpretq_u8_u64(a);
        let not_u8 = vmvnq_u8(as_u8);
        vreinterpretq_u64_u8(not_u8)
    }

    /// Vectorized Goldilocks subtraction: (a - b) mod P
    #[inline(always)]
    unsafe fn goldilocks_sub_vec(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
        // subtraction = a - b (wrapping)
        let subtraction = vsubq_u64(a, b);

        // Check for underflow: if a < b, underflow occurred
        let underflow = vcltq_u64(a, b);

        // If underflow, add P back
        let p_vec = vdupq_n_u64(P);
        let corrected = vaddq_u64(subtraction, p_vec);

        // Select: use corrected if underflow, else subtraction
        vbslq_u64(underflow, corrected, subtraction)
    }

    /// Vectorized Goldilocks multiplication: (a * b) mod P
    ///
    /// Decomposes 64-bit multiplication into 32-bit parts using the Goldilocks
    /// reduction formula.
    #[inline(always)]
    unsafe fn goldilocks_mul_vec(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
        // Split into 32-bit halves
        // a = a_lo + a_hi * 2^32
        // b = b_lo + b_hi * 2^32
        let mask32 = vdupq_n_u64(0xFFFFFFFF);
        let a_lo = vandq_u64(a, mask32);
        let a_hi = vshrq_n_u64(a, 32);
        let b_lo = vandq_u64(b, mask32);
        let b_hi = vshrq_n_u64(b, 32);

        // Compute the four 32x32->64 products
        // P0 = a_lo * b_lo (bits 0-63 of result)
        // P1 = a_lo * b_hi (bits 32-95 of result)
        // P2 = a_hi * b_lo (bits 32-95 of result)
        // P3 = a_hi * b_hi (bits 64-127 of result)

        // Extract as 32-bit vectors for vmull
        let a_lo_32 = vmovn_u64(a_lo);
        let a_hi_32 = vmovn_u64(a_hi);
        let b_lo_32 = vmovn_u64(b_lo);
        let b_hi_32 = vmovn_u64(b_hi);

        let p0 = vmull_u32(a_lo_32, b_lo_32);
        let p1 = vmull_u32(a_lo_32, b_hi_32);
        let p2 = vmull_u32(a_hi_32, b_lo_32);
        let p3 = vmull_u32(a_hi_32, b_hi_32);

        // Combine: result = p0 + (p1 + p2) << 32 + p3 << 64
        // We need to handle carries carefully.

        // mid = p1 + p2
        let mid = vaddq_u64(p1, p2);

        // Split mid into low and high 32 bits (for the shift)
        let mid_lo = vshlq_n_u64(vandq_u64(mid, mask32), 32);
        let mid_hi = vshrq_n_u64(mid, 32);

        // Carry from p1 + p2 overflow (if mid < p1)
        let mid_carry = vcltq_u64(mid, p1);
        let mid_carry_val =
            vandq_u64(vreinterpretq_u64_s64(vreinterpretq_s64_u64(mid_carry)), vdupq_n_u64(1));

        // lo = p0 + mid_lo
        let lo = vaddq_u64(p0, mid_lo);
        let lo_carry = vcltq_u64(lo, p0);
        let lo_carry_val =
            vandq_u64(vreinterpretq_u64_s64(vreinterpretq_s64_u64(lo_carry)), vdupq_n_u64(1));

        // hi = p3 + mid_hi + lo_carry + (mid_carry << 32)
        let hi = vaddq_u64(p3, mid_hi);
        let hi = vaddq_u64(hi, lo_carry_val);
        let hi = vaddq_u64(hi, vshlq_n_u64(mid_carry_val, 32));

        // Now reduce: lo + hi * 2^64 mod P
        // Using: 2^64 = 2^32 - 1 mod P and 2^96 = -1 mod P
        // x = c * 2^96 + b * 2^64 + a
        // x = b * (2^32 - 1) + (a - c) mod P
        goldilocks_reduce_128_vec(lo, hi)
    }

    /// Reduce a 128-bit value (lo + hi * 2^64) modulo P.
    ///
    /// Uses the Goldilocks reduction formula:
    /// - 2^64 = 2^32 - 1 (mod P)
    /// - 2^96 = -1 (mod P)
    ///
    /// So if x = c * 2^96 + b * 2^64 + a, then:
    /// x = b * (2^32 - 1) + (a - c) mod P
    #[inline(always)]
    unsafe fn goldilocks_reduce_128_vec(lo: uint64x2_t, hi: uint64x2_t) -> uint64x2_t {
        let mask32 = vdupq_n_u64(0xFFFFFFFF);

        // a = lo (low 64 bits)
        // b = hi & 0xFFFFFFFF (bits 64-95)
        // c = hi >> 32 (bits 96-127)
        let a = lo;
        let b = vandq_u64(hi, mask32);
        let c = vshrq_n_u64(hi, 32);

        // b_term = (b << 32) - b = b * (2^32 - 1)
        let b_shifted = vshlq_n_u64(b, 32);
        let b_term = vsubq_u64(b_shifted, b);

        // result = a - c + b_term
        // We need to handle underflow in (a - c) carefully

        // First: a - c (may underflow)
        let a_minus_c = vsubq_u64(a, c);
        let underflow = vcltq_u64(a, c);
        let p_vec = vdupq_n_u64(P);
        let a_minus_c_corrected = vaddq_u64(
            a_minus_c,
            vandq_u64(vreinterpretq_u64_s64(vreinterpretq_s64_u64(underflow)), p_vec),
        );

        // Then add b_term
        goldilocks_add_vec(a_minus_c_corrected, b_term)
    }

    /// Vectorized Goldilocks division by 2.
    #[inline(always)]
    unsafe fn goldilocks_div2_vec(a: uint64x2_t) -> uint64x2_t {
        // If a is even, just shift right by 1
        // If a is odd, add P first (making it even), then shift
        // Note: adding P can overflow, so we need to handle the carry

        let one = vdupq_n_u64(1);
        let p_vec = vdupq_n_u64(P);
        let high_bit = vdupq_n_u64(1u64 << 63);

        // Check if odd (low bit set)
        let is_odd = vandq_u64(a, one);
        let is_odd_mask = vceqq_u64(is_odd, one);

        // For odd: (a + P) >> 1, handling overflow
        // If a + P overflows (i.e., if a_plus_p < a), we need to set the high bit
        let a_plus_p = vaddq_u64(a, p_vec);
        let overflow = vcltq_u64(a_plus_p, a);

        // If overflow occurred, the result is (high_bit) | (a_plus_p >> 1)
        // Otherwise, the result is just a_plus_p >> 1
        let a_plus_p_shifted = vshrq_n_u64(a_plus_p, 1);
        let overflow_correction = vandq_u64(overflow, high_bit);
        let odd_result = vorrq_u64(a_plus_p_shifted, overflow_correction);

        // For even: just shift
        let even_result = vshrq_n_u64(a, 1);

        // Select based on oddness
        vbslq_u64(is_odd_mask, odd_result, even_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::Ring as _;

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
        // Forward then inverse should be identity
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
            // Test with values close to P to stress reduction
            let p_minus_1 = F::from(u64::MAX);
            let w = F::from(0xABCDEF0123456789u64);

            let mut a = vec![p_minus_1; 4];
            let mut b = vec![p_minus_1; 4];
            let mut a_scalar = a.clone();
            let mut b_scalar = b.clone();

            butterfly::<true>(&mut a, &mut b, w);
            butterfly_scalar::<true>(&mut a_scalar, &mut b_scalar, w);

            assert_eq!(a, a_scalar);
            assert_eq!(b, b_scalar);
        }
    }
}
