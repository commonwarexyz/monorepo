//! Native implementation of the AArch64 NEON instruction profile.

use crate::{Neon, Operation, Simd};
use core::arch::aarch64::{uint64x2_t, vaddq_u64, vdupq_n_u64, vld1q_u64, vst1q_u64};

/// Native NEON execution token with two unsigned 64-bit lanes.
///
/// Constructed only after checking for NEON support. Copies preserve this guarantee,
/// so vector instructions and child operations need no additional feature checks.
///
/// # Examples
///
/// ```
/// # #[cfg(target_arch = "aarch64")]
/// # {
/// use commonware_simd::{native::NativeNeon, Simd};
///
/// if let Some(s) = NativeNeon::new() {
///     let sum = s.u64_add(s.u64_load(&[1, u64::MAX]), s.u64_splat(1));
///     let mut output = [0; 2];
///     s.u64_store(sum, &mut output);
///     assert_eq!(output, [2, 0]);
/// }
/// # }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct NativeNeon(());

impl NativeNeon {
    /// Returns a token if the current CPU supports NEON.
    pub fn new() -> Option<Self> {
        std::arch::is_aarch64_feature_detected!("neon").then_some(Self(()))
    }

    // Fold the intrinsic and length check into feature-scoped downstream loops.
    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn load(input: &[u64]) -> uint64x2_t {
        assert!(input.len() >= Self::U64_LANES);
        // SAFETY: The slice contains two readable u64 lanes. The intrinsic accepts
        // unaligned vectors, and this function establishes the NEON feature scope.
        unsafe { vld1q_u64(input.as_ptr()) }
    }

    // Fold the intrinsic and length check into feature-scoped downstream loops.
    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn store(value: uint64x2_t, output: &mut [u64]) {
        assert!(output.len() >= Self::U64_LANES);
        // SAFETY: The slice contains two writable u64 lanes. The intrinsic accepts
        // unaligned vectors, and this function establishes the NEON feature scope.
        unsafe { vst1q_u64(output.as_mut_ptr(), value) };
    }

    // Remove the broadcast helper call from downstream kernel setup.
    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn splat(value: u64) -> uint64x2_t {
        vdupq_n_u64(value)
    }

    #[target_feature(enable = "neon")]
    unsafe fn add(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
        vaddq_u64(a, b)
    }

    // Keep consumer kernels in this feature scope instead of outlining them into a baseline scope.
    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn execute_neon<O: Operation>(self, operation: O) -> O::Output {
        operation.neon(self)
    }
}

impl Simd for NativeNeon {
    type U64 = uint64x2_t;

    const U64_LANES: usize = 2;

    // Expose the adapter so downstream loops can inline the feature-gated load.
    #[inline]
    fn u64_load(self, input: &[u64]) -> Self::U64 {
        // SAFETY: Construction of this token established NEON support.
        unsafe { Self::load(input) }
    }

    // Expose the adapter so downstream loops can inline the feature-gated store.
    #[inline]
    fn u64_store(self, value: Self::U64, output: &mut [u64]) {
        // SAFETY: Construction of this token established NEON support.
        unsafe { Self::store(value, output) };
    }

    // Remove the adapter call from downstream broadcast setup.
    #[inline]
    fn u64_splat(self, value: u64) -> Self::U64 {
        // SAFETY: Construction of this token established NEON support.
        unsafe { Self::splat(value) }
    }

    // Fold lane addition into feature-scoped downstream loops instead of calling per vector.
    #[inline]
    fn u64_add(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        // SAFETY: Construction of this token established NEON support.
        unsafe { Self::add(a, b) }
    }

    // Keep bulk computation in the native scope when reentering from an outlined consumer.
    #[inline]
    fn execute<O: Operation>(self, operation: O) -> O::Output {
        // SAFETY: Construction of this token established NEON support. This wrapper
        // reestablishes the feature scope when executing a root or child operation.
        unsafe { self.execute_neon(operation) }
    }
}

impl Neon for NativeNeon {}

#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz;
