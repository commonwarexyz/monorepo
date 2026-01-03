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

    /// NEON butterfly implementation.
    ///
    /// # Safety
    /// - `a` and `b` must point to valid memory for at least `chunks * 2` u64 elements
    /// - Pointers must be properly aligned for u64 access
    #[target_feature(enable = "neon")]
    unsafe fn butterfly_neon<const FORWARD: bool>(a: *mut u64, b: *mut u64, w: u64, chunks: usize) {
        let w_vec = vdupq_n_u64(w);

        for i in 0..chunks {
            let offset = i * 2;

            let a_vec = vld1q_u64(a.add(offset));
            let b_vec = vld1q_u64(b.add(offset));

            let (new_a, new_b) = if FORWARD {
                // Forward: (a + w*b, a - w*b)
                let wb_vec = goldilocks_mul_vec(w_vec, b_vec);
                let sum = goldilocks_add_vec(a_vec, wb_vec);
                let diff = goldilocks_sub_vec(a_vec, wb_vec);
                (sum, diff)
            } else {
                // Inverse: ((a + b)/2, (a - b)*w/2)
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
}
