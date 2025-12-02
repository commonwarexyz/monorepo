//! SIMD-accelerated field operations for the Goldilocks field.
//!
//! This module provides vectorized operations for processing multiple field
//! elements in parallel, primarily targeting the NTT hot paths.
//!
//! # Status
//!
//! In development.

use crate::field::F;

/// The modulus P := 2^64 - 2^32 + 1.
const P: u64 = u64::wrapping_neg(1 << 32) + 1;

// NEON SIMD implementation for aarch64
#[cfg(target_arch = "aarch64")]
mod neon {
    use super::*;
    use std::arch::aarch64::*;

    /// A pair of field elements stored in a NEON 128-bit register.
    #[derive(Clone, Copy)]
    #[repr(transparent)]
    pub struct F2(uint64x2_t);

    impl F2 {
        /// Load two consecutive field elements from a slice.
        ///
        /// # Safety
        ///
        /// The pointer must be valid for reading 2 u64 values.
        #[inline(always)]
        pub unsafe fn load(ptr: *const F) -> Self {
            Self(vld1q_u64(ptr as *const u64))
        }

        /// Store two field elements to consecutive memory locations.
        ///
        /// # Safety
        ///
        /// The pointer must be valid for writing 2 u64 values.
        #[inline(always)]
        pub unsafe fn store(self, ptr: *mut F) {
            vst1q_u64(ptr as *mut u64, self.0);
        }

        /// Create from two field elements.
        #[inline(always)]
        pub fn new(a: F, b: F) -> Self {
            let arr = [a.as_u64(), b.as_u64()];
            // SAFETY: vld1q_u64 from a valid array is safe
            unsafe { Self(vld1q_u64(arr.as_ptr())) }
        }

        /// Extract the two field elements.
        #[inline(always)]
        pub fn unpack(self) -> (F, F) {
            let mut arr = [0u64; 2];
            // SAFETY: vst1q_u64 to a valid array is safe
            unsafe { vst1q_u64(arr.as_mut_ptr(), self.0) };
            (F::from_raw(arr[0]), F::from_raw(arr[1]))
        }

        /// Add two pairs of field elements: (a0+b0, a1+b1) mod P.
        #[inline(always)]
        pub fn add(self, other: Self) -> Self {
            // SAFETY: All NEON intrinsics used are safe when operating on valid registers
            unsafe {
                let p = vdupq_n_u64(P);

                // addition = self + other (wrapping)
                let addition = vaddq_u64(self.0, other.0);

                // Check for overflow: if addition < self, we overflowed
                let overflow = vcltq_u64(addition, self.0);

                // subtraction = addition - P (wrapping)
                let subtraction = vsubq_u64(addition, p);

                // Check for underflow: if subtraction > addition, we underflowed
                let underflow = vcgtq_u64(subtraction, addition);

                // Use subtraction if overflow OR no underflow
                // mask = overflow | ~underflow
                // NEON doesn't have vmvnq_u64, so use XOR with all-ones
                let all_ones = vdupq_n_u64(u64::MAX);
                let not_underflow = veorq_u64(underflow, all_ones);
                let use_subtraction = vorrq_u64(overflow, not_underflow);

                // Select: if use_subtraction then subtraction else addition
                Self(vbslq_u64(use_subtraction, subtraction, addition))
            }
        }

        /// Subtract two pairs of field elements: (a0-b0, a1-b1) mod P.
        #[inline(always)]
        pub fn sub(self, other: Self) -> Self {
            // SAFETY: All NEON intrinsics used are safe when operating on valid registers
            unsafe {
                let p = vdupq_n_u64(P);

                // subtraction = self - other (wrapping)
                let subtraction = vsubq_u64(self.0, other.0);

                // Check for underflow: if self < other
                let underflow = vcltq_u64(self.0, other.0);

                // If underflow, add P back
                let addition = vaddq_u64(subtraction, p);

                // Select: if underflow then addition else subtraction
                Self(vbslq_u64(underflow, addition, subtraction))
            }
        }

        /// Multiply each element by a scalar: (a0*s, a1*s) mod P.
        ///
        /// This uses scalar multiplication with vectorized reduction.
        #[inline(always)]
        pub fn mul_scalar(self, scalar: F) -> Self {
            // For now, use scalar multiplication as NEON lacks efficient
            // u64 x u64 -> u128 widening multiply.
            let (a, b) = self.unpack();
            Self::new(a * scalar, b * scalar)
        }

        /// Divide each element by 2: (a0/2, a1/2) mod P.
        #[inline(always)]
        pub fn div_2(self) -> Self {
            // SAFETY: All NEON intrinsics used are safe when operating on valid registers
            unsafe {
                let p = vdupq_n_u64(P);
                let one = vdupq_n_u64(1);
                let high_bit = vdupq_n_u64(1u64 << 63);

                // Check if odd: (self & 1) != 0
                let is_odd = vandq_u64(self.0, one);
                let is_odd_mask = vceqq_u64(is_odd, one);

                // For odd values: (self + P) >> 1, handling carry
                // For even values: self >> 1
                let with_p = vaddq_u64(self.0, p);

                // Detect overflow: if with_p < self, there was a carry
                let overflow = vcltq_u64(with_p, self.0);

                // Select which value to shift (only matters for odd values)
                let to_shift = vbslq_u64(is_odd_mask, with_p, self.0);

                // Shift right by 1
                let shifted = vshrq_n_u64::<1>(to_shift);

                // If overflow occurred AND value was odd, set high bit
                let needs_high_bit = vandq_u64(overflow, is_odd_mask);
                let with_high_bit = vorrq_u64(shifted, vandq_u64(needs_high_bit, high_bit));

                Self(with_high_bit)
            }
        }
    }

    /// Process a forward NTT butterfly on 2 columns at once.
    ///
    /// Computes: a' = a + w*b, b' = a - w*b
    ///
    /// # Safety
    ///
    /// - `ptr_a` and `ptr_b` must be valid for reading and writing 2 F elements.
    /// - The memory regions must not overlap.
    #[inline(always)]
    pub unsafe fn butterfly_forward_2(ptr_a: *mut F, ptr_b: *mut F, w: F) {
        let a = F2::load(ptr_a);
        let b = F2::load(ptr_b);

        // t = w * b
        let t = b.mul_scalar(w);

        // a' = a + t, b' = a - t
        let a_new = a.add(t);
        let b_new = a.sub(t);

        a_new.store(ptr_a);
        b_new.store(ptr_b);
    }

    /// Process an inverse NTT butterfly on 2 columns at once.
    ///
    /// Computes: a' = (a + b) / 2, b' = (a - b) * w / 2
    ///
    /// # Safety
    ///
    /// - `ptr_a` and `ptr_b` must be valid for reading and writing 2 F elements.
    /// - The memory regions must not overlap.
    #[inline(always)]
    pub unsafe fn butterfly_inverse_2(ptr_a: *mut F, ptr_b: *mut F, w: F) {
        let a = F2::load(ptr_a);
        let b = F2::load(ptr_b);

        // sum = a + b, diff = a - b
        let sum = a.add(b);
        let diff = a.sub(b);

        // a' = sum / 2
        let a_new = sum.div_2();

        // b' = (diff * w) / 2
        let b_new = diff.mul_scalar(w).div_2();

        a_new.store(ptr_a);
        b_new.store(ptr_b);
    }
}

// Fallback scalar implementation
#[cfg(not(target_arch = "aarch64"))]
mod scalar {
    use super::*;

    /// Process a forward NTT butterfly on 2 columns at once (scalar fallback).
    #[inline(always)]
    pub unsafe fn butterfly_forward_2(ptr_a: *mut F, ptr_b: *mut F, w: F) {
        for i in 0..2 {
            let a = *ptr_a.add(i);
            let b = *ptr_b.add(i);
            let t = w * b;
            *ptr_a.add(i) = a + t;
            *ptr_b.add(i) = a - t;
        }
    }

    /// Process an inverse NTT butterfly on 2 columns at once (scalar fallback).
    #[inline(always)]
    pub unsafe fn butterfly_inverse_2(ptr_a: *mut F, ptr_b: *mut F, w: F) {
        for i in 0..2 {
            let a = *ptr_a.add(i);
            let b = *ptr_b.add(i);
            *ptr_a.add(i) = (a + b).div_2();
            *ptr_b.add(i) = ((a - b) * w).div_2();
        }
    }
}

// Re-export the appropriate implementation
#[cfg(target_arch = "aarch64")]
pub use neon::{butterfly_forward_2, butterfly_inverse_2};
#[cfg(not(target_arch = "aarch64"))]
pub use scalar::{butterfly_forward_2, butterfly_inverse_2};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_butterfly_forward_roundtrip() {
        let a = [F::from(100u64), F::from(200u64)];
        let b = [F::from(300u64), F::from(400u64)];
        let w = F::from(7u64);
        let w_inv = w.inv();

        let mut a_copy = a;
        let mut b_copy = b;

        // Forward butterfly
        unsafe {
            butterfly_forward_2(a_copy.as_mut_ptr(), b_copy.as_mut_ptr(), w);
        }

        // Inverse butterfly
        unsafe {
            butterfly_inverse_2(a_copy.as_mut_ptr(), b_copy.as_mut_ptr(), w_inv);
        }

        assert_eq!(a_copy, a);
        assert_eq!(b_copy, b);
    }

    #[test]
    fn test_butterfly_forward_matches_scalar() {
        let a = [F::from(12345u64), F::from(67890u64)];
        let b = [F::from(11111u64), F::from(22222u64)];
        let w = F::ROOT_OF_UNITY;

        // Compute expected values using scalar operations
        let expected_a = [a[0] + w * b[0], a[1] + w * b[1]];
        let expected_b = [a[0] - w * b[0], a[1] - w * b[1]];

        let mut a_simd = a;
        let mut b_simd = b;

        unsafe {
            butterfly_forward_2(a_simd.as_mut_ptr(), b_simd.as_mut_ptr(), w);
        }

        assert_eq!(a_simd, expected_a);
        assert_eq!(b_simd, expected_b);
    }

    #[test]
    fn test_butterfly_inverse_matches_scalar() {
        let a = [F::from(12345u64), F::from(67890u64)];
        let b = [F::from(11111u64), F::from(22222u64)];
        let w = F::ROOT_OF_UNITY;

        // Compute expected values using scalar operations
        let expected_a = [(a[0] + b[0]).div_2(), (a[1] + b[1]).div_2()];
        let expected_b = [((a[0] - b[0]) * w).div_2(), ((a[1] - b[1]) * w).div_2()];

        let mut a_simd = a;
        let mut b_simd = b;

        unsafe {
            butterfly_inverse_2(a_simd.as_mut_ptr(), b_simd.as_mut_ptr(), w);
        }

        assert_eq!(a_simd, expected_a);
        assert_eq!(b_simd, expected_b);
    }

    #[cfg(target_arch = "aarch64")]
    mod neon_tests {
        use super::{super::neon::F2, *};

        #[test]
        fn test_f2_add() {
            let a = F2::new(F::from(100u64), F::from(200u64));
            let b = F2::new(F::from(300u64), F::from(400u64));

            let result = a.add(b);
            let (r0, r1) = result.unpack();

            assert_eq!(r0, F::from(100u64) + F::from(300u64));
            assert_eq!(r1, F::from(200u64) + F::from(400u64));
        }

        #[test]
        fn test_f2_sub() {
            let a = F2::new(F::from(500u64), F::from(600u64));
            let b = F2::new(F::from(100u64), F::from(200u64));

            let result = a.sub(b);
            let (r0, r1) = result.unpack();

            assert_eq!(r0, F::from(500u64) - F::from(100u64));
            assert_eq!(r1, F::from(600u64) - F::from(200u64));
        }

        #[test]
        fn test_f2_sub_underflow() {
            let a = F2::new(F::from(100u64), F::from(200u64));
            let b = F2::new(F::from(500u64), F::from(600u64));

            let result = a.sub(b);
            let (r0, r1) = result.unpack();

            assert_eq!(r0, F::from(100u64) - F::from(500u64));
            assert_eq!(r1, F::from(200u64) - F::from(600u64));
        }

        #[test]
        fn test_f2_div_2() {
            // Test even numbers
            let a = F2::new(F::from(100u64), F::from(200u64));
            let result = a.div_2();
            let (r0, r1) = result.unpack();

            assert_eq!(r0, F::from(100u64).div_2());
            assert_eq!(r1, F::from(200u64).div_2());

            // Test odd numbers
            let b = F2::new(F::from(101u64), F::from(201u64));
            let result = b.div_2();
            let (r0, r1) = result.unpack();

            assert_eq!(r0, F::from(101u64).div_2());
            assert_eq!(r1, F::from(201u64).div_2());
        }
    }
}
